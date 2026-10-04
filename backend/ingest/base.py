"""Parser framework. Parsers emit *drafts* (plain dicts); the framework builds Events with stable IDs."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# line result kinds
EVENT = "event"
SKIP = "skip"
QUARANTINE = "quarantine"


@dataclass
class IngestContext:
    case_id: str
    assume_year: int | None = None  # for syslog lines that carry no year
    assume_tz_offset_min: int = 0  # for timestamps that carry no tz (syslog, naive ISO)


@dataclass
class FileCtx:
    filename: str
    host_hint: str | None
    year: int
    tz_offset_min: int
    year_inferred: bool = False
    state: dict[str, Any] = field(default_factory=dict)


class Parser(Protocol):
    name: str

    def detect(self, sample: list[str], filename: str) -> float: ...

    def parse_line(self, line: str, line_no: int, fctx: FileCtx) -> tuple[str, Any]:
        """-> (EVENT, draft dict) | (SKIP, reason) | (QUARANTINE, reason)"""
        ...
