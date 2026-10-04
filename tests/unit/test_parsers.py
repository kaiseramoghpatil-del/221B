"""Golden-line tests for every parser, including the awkward cases."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.core.models import Action, Category, Outcome
from backend.ingest import IngestContext, ingest_files


def one(name: str, text: str, **ctx):
    r = ingest_files([(name, text.encode())], IngestContext(case_id="t", **ctx))
    return r


def ev(name: str, line: str, **ctx):
    r = one(name, line + "\n", **ctx)
    assert len(r.events) == 1, (r.report, r.quarantine)
    return r.events[0]


# ----------------------------------------------------------------------- sshd / syslog
def test_sshd_accepted():
    e = ev("auth.log", "Sep 30 03:12:04 bastion-01 sshd[2411]: Accepted password for h.petrov from 198.19.76.39 port 51234 ssh2", assume_year=2026)
    assert (e.action, e.outcome, e.category) == (Action.login, Outcome.success, Category.authentication)
    assert (e.user, e.src_ip, e.host, e.object, e.session_id) == ("h.petrov", "198.19.76.39", "bastion-01", "password", "bastion-01:2411")
    assert e.ts_utc == datetime(2026, 9, 30, 3, 12, 4, tzinfo=timezone.utc) and e.tz_assumed
    assert "inferred_year" in e.parse_flags


def test_sshd_failed_invalid_user_flag():
    e = ev("auth.log", "Sep 30 03:12:04 bastion-01 sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", assume_year=2026)
    assert (e.action, e.outcome, e.user) == (Action.login, Outcome.failure, "admin")
    assert "invalid_user" in e.parse_flags


def test_sshd_failed_valid_user_no_flag():
    e = ev("auth.log", "Sep 30 03:12:04 bastion-01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", assume_year=2026)
    assert e.outcome is Outcome.failure and "invalid_user" not in e.parse_flags


def test_sshd_invalid_user_notice_is_not_a_failure():
    """'Invalid user' accompanies 'Failed password for invalid user' - counting both would double-count failures."""
    e = ev("auth.log", "Sep 30 03:12:04 bastion-01 sshd[1]: Invalid user oracle from 1.2.3.4 port 5555", assume_year=2026)
    assert e.action is Action.other and e.object == "invalid_user" and e.outcome is Outcome.unknown


def test_sshd_preauth_close_and_session_close():
    a = ev("auth.log", "Sep 30 03:12:04 h sshd[7]: Connection closed by invalid user bob 9.9.9.9 port 11 [preauth]", assume_year=2026)
    assert a.object == "preauth_close" and a.src_ip == "9.9.9.9" and a.user == "bob"
    b = ev("auth.log", "Sep 30 03:12:04 h sshd[7]: pam_unix(sshd:session): session closed for user alice", assume_year=2026)
    assert (b.action, b.user, b.session_id) == (Action.logout, "alice", "h:7")


def test_sudo_and_useradd_and_group():
    s = ev("auth.log", "Sep 30 03:12:04 app-01 sudo:   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash -c 'id'", assume_year=2026)
    assert (s.action, s.category, s.user, s.object) == (Action.sudo, Category.iam, "alice", "/bin/bash -c 'id'")
    assert s.attrs["target_user"] == "root"
    u = ev("auth.log", "Sep 30 03:12:04 app-01 useradd[99]: new user: name=n.hire, UID=1900, GID=1900, home=/home/n.hire, shell=/bin/bash", assume_year=2026)
    assert (u.action, u.object) == (Action.useradd, "n.hire")
    g = ev("auth.log", "Sep 30 03:12:04 app-01 usermod[99]: add 'n.hire' to group 'developers'", assume_year=2026)
    assert (g.action, g.object) == (Action.group_add, "n.hire:developers")


def test_iso_syslog_with_timezone():
    e = ev("auth.log", "2026-09-30T08:42:04.123456+05:30 web-01 sshd[5]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2")
    assert e.ts_utc == datetime(2026, 9, 30, 3, 12, 4, 123456, tzinfo=timezone.utc) and not e.tz_assumed


def test_syslog_year_rollover_dec_to_jan():
    text = ("Dec 31 23:59:58 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\n"
            "Jan  1 00:00:02 h sshd[2]: Accepted password for a from 1.1.1.1 port 1 ssh2\n")
    r = one("auth.log", text, assume_year=2026)
    assert [e.ts_utc.year for e in r.events] == [2026, 2027]


def test_syslog_unhandled_is_skipped_not_quarantined():
    r = one("auth.log", "Sep 30 03:12:04 h CRON[1]: (root) CMD (run-parts /etc/cron.hourly)\nSep 30 03:12:05 h sshd[2]: Accepted password for a from 1.1.1.1 port 1 ssh2\n", assume_year=2026)
    f = r.source_files[0]
    assert (f.lines_parsed, f.lines_skipped, f.lines_quarantined) == (1, 1, 0)
    assert f.skipped_reasons == {"unhandled:CRON": 1}


def test_syslog_garbage_line_quarantined_with_reason():
    good = "Sep 30 03:12:04 h sshd[2]: Accepted password for a from 1.1.1.1 port 1 ssh2\n"
    r = one("auth.log", good * 5 + "\x01\x02 not a log line\n", assume_year=2026)
    assert len(r.events) == 5 and len(r.quarantine) == 1
    assert r.quarantine[0].reason == "no_syslog_prefix" and r.quarantine[0].line_no == 6


def test_syslog_impossible_date_quarantined():
    good = "Sep 30 03:12:04 h sshd[2]: Accepted password for a from 1.1.1.1 port 1 ssh2\n"
    r = one("auth.log", good * 5 + "Feb 30 03:12:04 h sshd[2]: Accepted password for a from 1.1.1.1 port 1 ssh2\n", assume_year=2026)
    assert len(r.events) == 5 and r.quarantine[0].reason.startswith("bad_timestamp")


def test_nginx_non_numeric_bytes_does_not_crash():
    line = '1.2.3.4 - - [30/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 :5 "-" "x"'
    e = ev("access.log", line)
    assert e.bytes_out is None


# ----------------------------------------------------------------------- web
def test_nginx_combined_with_offset_and_host_hint():
    line = '198.19.134.230 - - [28/Sep/2026:05:30:04 +0530] "GET /api/v1/items/42 HTTP/1.1" 404 3030 "-" "Googlebot/2.1"'
    e = ev("access-web-02.log", line)
    assert e.host == "web-02" and e.ts_utc == datetime(2026, 9, 28, 0, 0, 4, tzinfo=timezone.utc)
    assert (e.action, e.category, e.outcome, e.object, e.bytes_out) == (Action.http, Category.web, Outcome.failure, "GET /api/v1/items/42", 3030)
    assert e.attrs["status"] == 404 and e.user is None and e.user_agent == "Googlebot/2.1"


def test_nginx_auth_user_and_dash_bytes():
    e = ev("access.log", '1.2.3.4 - alice [01/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 302 - "-" "curl/8"')
    assert e.user == "alice" and e.bytes_out is None and e.outcome is Outcome.success


# ----------------------------------------------------------------------- generic CSV / JSONL
def test_csv_firewall_aliases_and_outcome():
    text = "Timestamp,SrcAddr,DstAddr,DPort,Action,Bytes_Sent,Hostname\n2026-09-30T03:12:04Z,10.0.0.5,1.2.3.4,443,denied,120,fw1\n"
    r = one("fw.csv", text)
    e = r.events[0]
    assert (e.action, e.outcome, e.category) == (Action.conn, Outcome.failure, Category.network)
    assert (e.src_ip, e.dst_ip, e.dst_port, e.bytes_out, e.host) == ("10.0.0.5", "1.2.3.4", 443, 120, "fw1")


def test_csv_keeps_unmapped_columns_in_attrs():
    text = "time,src_ip,dst_ip,mystery_col\n2026-09-30 03:12:04,1.1.1.1,2.2.2.2,xyz\n"
    e = one("x.csv", text).events[0]
    assert e.attrs["mystery_col"] == "xyz" and "tz_assumed" in e.parse_flags


def test_csv_column_mismatch_quarantined():
    text = "time,src_ip,dst_ip\n2026-09-30 03:12:04,1.1.1.1\n"
    r = one("x.csv", text)
    assert not r.events and r.quarantine[0].reason.startswith("column_count_mismatch")


def test_jsonl_ecs_nested_names():
    line = '{"@timestamp":"2026-09-30T03:12:04Z","event":{"action":"login","outcome":"success"},"user":{"name":"alice"},"source":{"ip":"1.2.3.4"},"host":{"name":"web-01"}}'
    e = ev("ecs.jsonl", line)
    assert (e.action, e.outcome, e.user, e.src_ip, e.host) == (Action.login, Outcome.success, "alice", "1.2.3.4", "web-01")


def test_jsonl_epoch_ms_and_invalid_json():
    r = one("a.jsonl", '{"ts":1790000000000,"user":"u","event":"exec","object":"ls"}\n{not json}\n')
    assert len(r.events) == 1 and r.events[0].action is Action.proc_exec
    assert len(r.quarantine) == 1 and r.quarantine[0].reason == "invalid_json"


# ----------------------------------------------------------------------- framework behaviour
def test_unrecognized_format_is_quarantined_visibly():
    r = one("mystery.bin", "hello world\nthis is not a log\n")
    assert r.source_files[0].detected_format == "unknown"
    assert not r.events and r.report.lines_quarantined == 2
    assert any("not recognized" in n for n in r.report.notes)


def test_crlf_bom_and_blank_lines_keep_physical_line_numbers():
    text = "﻿Sep 30 03:12:04 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\r\n\r\nSep 30 03:12:05 h sshd[2]: Accepted password for b from 1.1.1.1 port 1 ssh2\r\n"
    r = ingest_files([("auth.log", text.encode("utf-8"))], IngestContext(case_id="t", assume_year=2026))
    assert [e.line_no for e in r.events] == [1, 3]


def test_year_borrowed_from_other_files_when_unspecified():
    web = b'1.2.3.4 - - [30/Sep/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"\n'
    sys_ = b"Sep 30 03:12:04 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\n"
    r = ingest_files([("auth.log", sys_), ("access-web-01.log", web)], IngestContext(case_id="t"))
    assert {e.ts_utc.year for e in r.events} == {2024}


def test_event_ids_stable_and_unique():
    text = "Sep 30 03:12:04 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2\n" * 3
    a = ingest_files([("auth.log", text.encode())], IngestContext(case_id="t", assume_year=2026))
    b = ingest_files([("auth.log", text.encode())], IngestContext(case_id="other", assume_year=2026))
    ids = [e.id for e in a.events]
    assert len(set(ids)) == 3 and ids == [e.id for e in b.events]
    assert all(i.startswith("E-") and len(i) == 14 for i in ids)
