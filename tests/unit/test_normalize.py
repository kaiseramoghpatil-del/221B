from __future__ import annotations

import random

from backend.ingest import IngestContext, ingest_files
from backend.normalize import is_internal, normalize

AUTH = """Sep 30 03:00:00 bastion-01 sshd[100]: Accepted password for alice from 198.18.5.5 port 5000 ssh2
Sep 30 03:05:00 app-01 sshd[200]: Accepted publickey for alice from 10.0.0.5 port 6000 ssh2
Sep 30 03:06:00 app-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
Sep 30 03:06:00 app-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
Sep 30 03:30:00 app-01 sshd[200]: pam_unix(sshd:session): session closed for user alice
Sep 30 04:00:00 bastion-01 sshd[100]: pam_unix(sshd:session): session closed for user alice
"""
FLOWS = """timestamp,src_host,src_ip,dst_ip,dst_port,protocol,bytes_out,bytes_in,action
2026-09-30T02:00:00Z,bastion-01,10.0.0.5,10.0.1.20,22,tcp,10,10,allowed
2026-09-30T02:00:00Z,app-01,10.0.1.20,10.0.1.30,5432,tcp,10,10,allowed
"""


def _nc(auth=AUTH, flows=FLOWS):
    r = ingest_files([("auth.log", auth.encode()), ("flows.csv", flows.encode())], IngestContext(case_id="t", assume_year=2026))
    return normalize(r.events)


def test_is_internal_is_strict_rfc1918():
    assert is_internal("10.1.2.3") and is_internal("192.168.0.1") and is_internal("172.20.0.1")
    # Python's is_private would say True for these; they are external from our point of view
    assert not is_internal("198.18.5.5") and not is_internal("100.64.0.1") and not is_internal("8.8.8.8")
    assert not is_internal(None) and not is_internal("garbage")


def test_ip_to_host_learned_from_flows():
    nc = _nc()
    assert nc.ip_to_host["10.0.0.5"] == "bastion-01" and nc.ip_to_host["10.0.1.20"] == "app-01"


def test_sessions_close_and_hop_lineage():
    nc = _nc()
    sess = sorted(nc.sessions.values(), key=lambda s: s.t_start)
    assert [(s.user, s.host) for s in sess] == [("alice", "bastion-01"), ("alice", "app-01")]
    root, hop = sess
    assert hop.parent == root.id and root.parent is None
    assert hop.t_end is not None and hop.t_end.hour == 3 and hop.t_end.minute == 30
    sudo = [e for e in nc.events if e.action.value == "sudo"]
    assert len(sudo) == 1, "adjacent duplicate must be collapsed"
    assert nc.session_of[sudo[0].id] == hop.id and nc.dup_collapsed == 1


def test_normalize_is_order_invariant():
    r = ingest_files([("auth.log", AUTH.encode()), ("flows.csv", FLOWS.encode())], IngestContext(case_id="t", assume_year=2026))
    a = normalize(r.events)
    evs = list(r.events)
    random.Random(3).shuffle(evs)
    b = normalize(evs)
    assert [e.id for e in a.events] == [e.id for e in b.events]
    assert {(s.user, s.host, s.parent is None) for s in a.sessions.values()} == {(s.user, s.host, s.parent is None) for s in b.sessions.values()}


def test_concurrent_sessions_leave_host_activity_unattributed():
    """Same account, two sessions open on the same host (e.g. victim and intruder): an audit line without tty/pid must
    not be pinned to whichever session started last."""
    auth = """Sep 30 03:00:00 bastion-01 sshd[100]: Accepted password for alice from 198.18.5.5 port 5000 ssh2
Sep 30 03:10:00 bastion-01 sshd[101]: Accepted password for alice from 198.19.9.9 port 5001 ssh2
"""
    audit = '{"ts":"2026-09-30T03:20:00Z","host":"bastion-01","user":"alice","event":"exec","object":"id"}\n'
    r = ingest_files([("auth.log", auth.encode()), ("audit.jsonl", audit.encode())], IngestContext(case_id="t", assume_year=2026))
    nc = normalize(r.events)
    ex = next(e for e in nc.events if e.action.value == "proc_exec")
    assert ex.id not in nc.session_of
