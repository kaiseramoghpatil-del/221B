"""Ingestion: format sniffing -> parser -> Events (+ quarantine, parse report).

Nothing is silently dropped: every line is either an Event, an explained skip (irrelevant message), or a
quarantine row with a reason. The pipeline never imports the scenario generator; it sees only bytes.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from backend.core.ids import event_id, file_id, sha1_hex
from backend.core.models import Event, ParseReport, QuarantineRow, SourceFile

from .base import EVENT, QUARANTINE, FileCtx, IngestContext
from .sshd import SshdSyslogParser
from .tabular import GenericCsvParser, GenericJsonlParser
from .web_access import WebAccessParser

__all__ = ["ingest_files", "IngestContext", "IngestResult", "PARSERS", "detect_format"]

PARSERS = [SshdSyslogParser(), WebAccessParser(), GenericCsvParser(), GenericJsonlParser()]
DETECT_THRESHOLD = 0.35
QUARANTINE_CAP_PER_FILE = 5000
_HOST_RE = re.compile(r"([A-Za-z][A-Za-z]*-\d+)")


@dataclass
class IngestResult:
    events: list[Event]
    quarantine: list[QuarantineRow]
    source_files: list[SourceFile]
    report: ParseReport
    lines_by_file: dict[str, list[str]] = field(default_factory=dict)  # file_id -> raw lines (evidence context)
    file_names: dict[str, str] = field(default_factory=dict)  # file_id -> name


def host_hint_from_name(name: str) -> str | None:
    m = _HOST_RE.search(name.rsplit("/", 1)[-1])
    return m.group(1).lower() if m else None


def split_lines(data: bytes) -> list[str]:
    text = data.decode("utf-8-sig", errors="replace")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [ln[:-1] if ln.endswith("\r") else ln for ln in lines]


def detect_format(lines: list[str], filename: str):
    sample = [ln for ln in lines[:80] if ln.strip()][:50]
    best, best_conf = None, 0.0
    for p in PARSERS:
        c = p.detect(sample, filename)
        if c > best_conf:
            best, best_conf = p, c
    if best is None or best_conf < DETECT_THRESHOLD:
        return None, best_conf
    return best, best_conf


def ingest_files(files: list[tuple[str, bytes]], ctx: IngestContext) -> IngestResult:
    prepared = []
    for name, data in files:
        lines = split_lines(data)
        parser, conf = detect_format(lines, name)
        prepared.append((name, data, lines, parser, conf, file_id(name, data)))

    # Non-syslog files first so year-less syslog can borrow a year from files that carry one.
    order = sorted(range(len(prepared)), key=lambda i: isinstance(prepared[i][3], SshdSyslogParser))
    years_seen: Counter[int] = Counter()
    events: list[Event] = []
    quarantine: list[QuarantineRow] = []
    sfiles: dict[int, SourceFile] = {}
    notes: list[str] = []
    lines_by_file: dict[str, list[str]] = {}
    file_names: dict[str, str] = {}

    for i in order:
        name, data, lines, parser, conf, fid = prepared[i]
        lines_by_file[fid] = lines
        file_names[fid] = name
        if parser is None:
            nq = 0
            for ln_no, ln in enumerate(lines, 1):
                if ln.strip():
                    nq += 1
                    if nq <= QUARANTINE_CAP_PER_FILE:
                        quarantine.append(QuarantineRow(file_id=fid, line_no=ln_no, raw_text=ln[:500], reason="unrecognized_format"))
            sfiles[i] = SourceFile(id=fid, case_id=ctx.case_id, name=name, sha1=sha1_hex(data)[:16], detected_format="unknown",
                                   parser_conf=conf, lines_total=len(lines), lines_parsed=0, lines_skipped=len(lines) - nq,
                                   lines_quarantined=nq, skipped_reasons={"blank": len(lines) - nq} if len(lines) > nq else {},
                                   host_hint=host_hint_from_name(name))
            notes.append(f"{name}: format not recognized; {nq} lines quarantined")
            continue

        is_sys = isinstance(parser, SshdSyslogParser)
        if is_sys:
            if ctx.assume_year:
                year, inferred = ctx.assume_year, False
            elif years_seen:
                year, inferred = years_seen.most_common(1)[0][0], True
            else:
                year, inferred = datetime.now(timezone.utc).year, True
        else:
            year, inferred = ctx.assume_year or datetime.now(timezone.utc).year, False
        fctx = FileCtx(filename=name, host_hint=host_hint_from_name(name), year=year,
                       tz_offset_min=ctx.assume_tz_offset_min, year_inferred=inferred)
        if is_sys and inferred:
            notes.append(f"{name}: syslog stamps carry no year; assumed {year} (borrowed from other files / clock)")
        if is_sys:
            notes.append(f"{name}: syslog stamps carry no timezone; assumed UTC{ctx.assume_tz_offset_min:+d}min")

        skipped: Counter[str] = Counter()
        flag_counts: Counter[str] = Counter()
        n_parsed = n_quar = 0
        for ln_no, ln in enumerate(lines, 1):
            if not ln.strip():
                skipped["blank"] += 1
                continue
            try:
                kind, payload = parser.parse_line(ln, ln_no, fctx)
            except Exception as exc:  # a parser bug or hostile line must never abort the whole ingest
                kind, payload = QUARANTINE, f"parser_error:{type(exc).__name__}"
            if kind == EVENT:
                d = payload
                ev = Event.model_construct(
                    id=event_id(fid, ln_no), case_id=ctx.case_id, file_id=fid, line_no=ln_no, raw_text=ln, **d
                )
                events.append(ev)
                n_parsed += 1
                for f in d["parse_flags"]:
                    flag_counts[f] += 1
                years_seen[d["ts_utc"].year] += 1
            elif kind == QUARANTINE:
                n_quar += 1
                if n_quar <= QUARANTINE_CAP_PER_FILE:
                    quarantine.append(QuarantineRow(file_id=fid, line_no=ln_no, raw_text=ln[:500], reason=str(payload)))
            else:
                skipped[str(payload)] += 1
        sfiles[i] = SourceFile(
            id=fid, case_id=ctx.case_id, name=name, sha1=sha1_hex(data)[:16], detected_format=parser.name, parser_conf=round(conf, 3),
            lines_total=len(lines), lines_parsed=n_parsed, lines_skipped=sum(skipped.values()), lines_quarantined=n_quar,
            skipped_reasons=dict(skipped), flag_counts=dict(flag_counts), host_hint=fctx.host_hint,
        )

    ordered_files = [sfiles[i] for i in range(len(prepared))]
    ts = [e.ts_utc for e in events]
    hosts = sorted({e.host for e in events if e.host})
    report = ParseReport(
        files=ordered_files, events_total=len(events), lines_total=sum(f.lines_total for f in ordered_files),
        lines_quarantined=sum(f.lines_quarantined for f in ordered_files), lines_skipped=sum(f.lines_skipped for f in ordered_files),
        t_min=min(ts) if ts else None, t_max=max(ts) if ts else None, hosts=hosts, notes=notes,
    )
    return IngestResult(events=events, quarantine=quarantine, source_files=ordered_files, report=report,
                        lines_by_file=lines_by_file, file_names=file_names)
