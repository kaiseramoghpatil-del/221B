"""Property tests: ingest must never crash and must account for every line."""
from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.ingest import IngestContext, ingest_files

SEEDS = [
    "Sep 30 03:12:04 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2",
    '1.2.3.4 - - [30/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"',
    "time,src_ip,dst_ip\n2026-09-30 03:12:04,1.1.1.1,2.2.2.2",
    '{"ts":"2026-09-30T03:12:04Z","user":"u","event":"exec","object":"ls"}',
]


def mutate(base: str, junk: str, cut: int) -> str:
    cut = cut % (len(base) + 1)
    return base[:cut] + junk + base[cut:]


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(st.lists(st.tuples(st.sampled_from(SEEDS), st.text(max_size=30), st.integers(0, 200)), min_size=1, max_size=40))
def test_every_line_is_accounted_for_and_nothing_crashes(rows):
    text = "\n".join(mutate(b, j, c).replace("\n", " ") for b, j, c in rows) + "\n"
    r = ingest_files([("fuzz.log", text.encode("utf-8", errors="replace"))], IngestContext(case_id="t", assume_year=2026))
    f = r.source_files[0]
    assert f.lines_total == f.lines_parsed + f.lines_skipped + f.lines_quarantined
    assert len(r.events) == f.lines_parsed
    assert len({e.id for e in r.events}) == len(r.events)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=2000))
def test_arbitrary_bytes_never_crash(data):
    r = ingest_files([("blob.bin", data)], IngestContext(case_id="t", assume_year=2026))
    f = r.source_files[0]
    assert f.lines_total == f.lines_parsed + f.lines_skipped + f.lines_quarantined
