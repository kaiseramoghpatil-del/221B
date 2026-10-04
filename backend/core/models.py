"""221B data contract (Pydantic v2).

FROZEN as contract v1.0.0 - see contract/CONTRACT.md. Engine, API and UI are built against
these models. Changing a field requires bumping CONTRACT_VERSION and regenerating
contract/openapi.json + frontend types.

Vocabulary is ECS-aligned (category / action / outcome). See docs/SPEC.md section 5.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.0.0"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------- enums
class Category(StrEnum):
    authentication = "authentication"
    network = "network"
    file = "file"
    process = "process"
    web = "web"
    iam = "iam"


class Outcome(StrEnum):
    success = "success"
    failure = "failure"
    unknown = "unknown"


class Action(StrEnum):
    login = "login"
    logout = "logout"
    sudo = "sudo"
    su = "su"
    useradd = "useradd"
    group_add = "group_add"
    http = "http"
    conn = "conn"
    file_read = "file_read"
    file_write = "file_write"
    proc_exec = "proc_exec"
    cron_add = "cron_add"
    key_add = "key_add"
    log_clear = "log_clear"
    other = "other"


class SourceType(StrEnum):
    auth = "auth"
    web = "web"
    net = "net"
    audit = "audit"
    sys = "sys"


class Stage(StrEnum):
    """Fixed kill-chain taxonomy (ATT&CK tactic names). Order = STAGE_ORDER."""

    RECON = "RECON"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIV_ESC = "PRIV_ESC"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"


STAGE_ORDER: dict[Stage, int] = {s: i for i, s in enumerate(Stage)}


class PredicateName(StrEnum):
    credential_compromised = "credential_compromised"
    has_access = "has_access"
    privileged = "privileged"
    foothold = "foothold"
    discovered = "discovered"
    staged = "staged"
    exfiltrated = "exfiltrated"
    persisted = "persisted"


class EntityType(StrEnum):
    user = "user"
    ip = "ip"
    host = "host"
    actor_cluster = "actor_cluster"


class Criticality(StrEnum):
    low = "low"
    med = "med"
    high = "high"


class EvidenceRole(StrEnum):
    supports = "supports"
    context = "context"
    contradicts = "contradicts"


class LinkKind(StrEnum):
    predicate = "predicate"
    soft = "soft"


class ClaimType(StrEnum):
    ENTRY = "ENTRY"
    ACTION = "ACTION"
    PIVOT = "PIVOT"
    ESCALATION = "ESCALATION"
    STAGING = "STAGING"
    EXFIL = "EXFIL"
    GAP = "GAP"
    CAVEAT = "CAVEAT"
    DISMISSAL = "DISMISSAL"


class IncidentStatus(StrEnum):
    incident = "incident"
    watchlist = "watchlist"


class WatchlistPriority(StrEnum):
    normal = "normal"
    high = "high"  # confirmed-impact single-stage finding


class EntityRole(StrEnum):
    attacker_infra = "attacker_infra"
    compromised_account = "compromised_account"
    pivot_host = "pivot_host"
    victim_host = "victim_host"
    noisy_benign = "noisy_benign"
    unknown = "unknown"


class CaseSource(StrEnum):
    upload = "upload"
    scenario = "scenario"


class CaseStatus(StrEnum):
    created = "created"
    parsing = "parsing"
    analyzing = "analyzing"
    ready = "ready"
    failed = "failed"


# --------------------------------------------------------------------------- ingestion
class SourceFile(_M):
    id: str
    case_id: str
    name: str
    sha1: str
    detected_format: str
    parser_conf: float = Field(ge=0, le=1)
    lines_total: int
    lines_parsed: int
    lines_skipped: int
    lines_quarantined: int
    skipped_reasons: dict[str, int] = Field(default_factory=dict)
    flag_counts: dict[str, int] = Field(default_factory=dict)
    host_hint: str | None = None


class QuarantineRow(_M):
    file_id: str
    line_no: int
    raw_text: str
    reason: str


class ParseReport(_M):
    files: list[SourceFile]
    events_total: int
    lines_total: int
    lines_quarantined: int
    lines_skipped: int
    t_min: datetime | None = None
    t_max: datetime | None = None
    hosts: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class Event(_M):
    id: str  # "E-" + sha1(file_id|line_no)[:12]
    case_id: str
    file_id: str
    line_no: int
    ts_utc: datetime
    ts_original: str
    tz_assumed: bool = False
    source_type: SourceType
    category: Category
    action: Action
    outcome: Outcome = Outcome.unknown
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    session_id: str | None = None
    object: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    user_agent: str | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)
    raw_text: str
    parse_flags: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- entities / sessions
class Entity(_M):
    id: str  # "user:mkessler" | "ip:1.2.3.4" | "host:db-01" | "cluster:A1"
    type: EntityType
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    role: EntityRole = EntityRole.unknown
    internal: bool | None = None
    subnet: str | None = None
    criticality: Criticality = Criticality.med
    attrs: dict[str, Any] = Field(default_factory=dict)


class LinkageEvidence(_M):
    kind: str  # ua | subnet | target_set | cadence | cred_list
    weight: float
    detail: str | None = None


class ActorCluster(_M):
    id: str
    member_ips: list[str]
    linkage_evidence: list[LinkageEvidence]
    total_weight: float


class Session(_M):
    id: str
    user: str
    host: str
    src_ip: str | None = None
    t_start: datetime
    t_end: datetime | None = None
    login_event_id: str
    event_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- evidence
class EvidenceRef(_M):
    event_id: str
    role: EvidenceRole = EvidenceRole.supports
    note: str | None = None


class RuleMeta(_M):
    level: str  # informational | low | medium | high | critical
    tags: list[str] = Field(default_factory=list)  # e.g. attack.credential_access
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class PredicateInstance(_M):
    name: PredicateName
    args: dict[str, str] = Field(default_factory=dict)  # user / host / ip / resource / dst / via
    t: datetime | None = None


# --------------------------------------------------------------------------- signals / incidents
class Signal(_M):
    id: str  # "S-..."
    detector: str  # "D03"
    title: str
    stage_hint: Stage
    entities: list[str]  # entity ids
    t_start: datetime
    t_end: datetime
    severity: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    rarity: float = Field(ge=0, le=1, default=0.5)
    criticality_mult: float = Field(ge=1, default=1.0)
    requires: list[PredicateInstance] = Field(default_factory=list)
    produces: list[PredicateInstance] = Field(default_factory=list)
    rule_meta: RuleMeta
    features: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRef]
    explanation_template: str
    explanation_params: dict[str, Any] = Field(default_factory=dict)


class Link(_M):
    signal_a: str
    signal_b: str
    kind: LinkKind
    via: PredicateInstance | None = None
    reason: str
    weight: float = 1.0


class AttackStep(_M):
    id: str
    order: int
    stage: Stage
    t_start: datetime
    t_end: datetime
    actor_entity: str | None = None
    target_entity: str | None = None
    signal_ids: list[str]
    event_ids: list[str]
    edge_justification: list[PredicateInstance] = Field(default_factory=list)
    inferred: bool = False  # True if continuity is inferred (gap)
    summary_count: int | None = None  # collapsed repeated events ("x11")


class Hypothesis(_M):
    id: str
    kind: str = "entry"
    description: str
    signal_ids: list[str]
    probability: float = Field(ge=0, le=1)


class Gap(_M):
    id: str
    kind: str  # unsatisfied_prerequisite | log_silence
    description: str
    host: str | None = None
    t_start: datetime | None = None
    t_end: datetime | None = None
    missing_predicate: PredicateInstance | None = None


class Claim(_M):
    id: str
    incident_id: str
    type: ClaimType
    text: str
    facts: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceRef]
    confidence: float = Field(ge=0, le=1)
    step_id: str | None = None


class Dismissal(_M):
    id: str
    entity: str
    decision: str = "not_flagged"
    reasons: list[str]
    counter_evidence: list[EvidenceRef] = Field(default_factory=list)
    would_flag_if: str | None = None


class ScoreItem(_M):
    signal_id: str
    strength: float
    consequence_factor: float
    contribution: float


class ScoreBreakdown(_M):
    incident_id: str
    items: list[ScoreItem]
    bonuses: dict[str, float] = Field(default_factory=dict)
    final: float
    confidence: float
    confidence_parts: dict[str, float] = Field(default_factory=dict)


class Incident(_M):
    id: str
    title: str
    scenario_id: str | None = None
    status: IncidentStatus
    signal_ids: list[str]
    entities: list[str]
    t_start: datetime
    t_end: datetime
    steps: list[AttackStep] = Field(default_factory=list)
    stages_covered: list[Stage] = Field(default_factory=list)  # incident => >= 2, predicate-joined
    watchlist_priority: WatchlistPriority | None = None  # only when status == watchlist
    watchlist_reason: str | None = None
    score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    entry_hypotheses: list[Hypothesis] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)


class ReplayFrame(_M):
    t: datetime
    nodes_added: list[str] = Field(default_factory=list)
    edges_added: list[str] = Field(default_factory=list)
    active_stage: Stage | None = None
    claim_id: str | None = None


class GraphNode(_M):
    id: str
    type: EntityType
    label: str
    role: EntityRole = EntityRole.unknown
    stage: Stage | None = None
    first_seen: datetime | None = None
    criticality: Criticality = Criticality.med


class GraphEdge(_M):
    id: str
    source: str
    target: str
    label: str
    t_start: datetime
    t_end: datetime
    count: int = 1  # summary-edge collapse
    inferred: bool = False
    predicate: str | None = None
    event_ids: list[str] = Field(default_factory=list)


class AttackGraph(_M):
    incident_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    frames: list[ReplayFrame]


# --------------------------------------------------------------------------- scenario + truth (shared with sim/, eval/)
class ScenarioParams(_M):
    """Validated ranges = the only knobs the UI may expose (sliders are capped here)."""

    template: str = Field(default="T1", pattern="^(T0|T1|T2)$")  # T0 clean, T1 stolen credential, T2 brute-force success
    stealth: float = Field(default=0.5, ge=0.0, le=1.0)
    ip_rotation: int = Field(default=1, ge=1, le=40)
    noise: float = Field(default=1.0, ge=0.2, le=3.0)
    log_loss: float = Field(default=0.0, ge=0.0, le=0.4)
    clock_skew_s: int = Field(default=0, ge=-900, le=900)
    dup_rate: float = Field(default=0.0, ge=0.0, le=0.2)
    shuffle: float = Field(default=0.0, ge=0.0, le=1.0)
    malformed_rate: float = Field(default=0.0, ge=0.0, le=0.05)
    scale: float = Field(default=1.0, ge=0.02, le=3.0)
    with_decoys: bool = True


class TruthRef(_M):
    file: str
    line: int


class TruthStage(_M):
    stage: Stage
    t_start: datetime
    t_end: datetime
    host: str | None = None
    actor_user: str | None = None
    refs: list[TruthRef] = Field(default_factory=list)


class TruthDecoy(_M):
    entity: str
    kind: str
    refs: list[TruthRef] = Field(default_factory=list)


class TruthGap(_M):
    kind: str  # dropped_events | silent_window
    host: str
    source: str
    t_start: datetime
    t_end: datetime
    n_dropped: int = 0


class GroundTruth(_M):
    scenario_id: str
    seed: int
    template: str
    params: ScenarioParams
    entry_vector: str | None = None  # stolen_credential | bruteforce_success | None (clean)
    attacker_ips: list[str] = Field(default_factory=list)
    exfil_dst_ips: list[str] = Field(default_factory=list)
    compromised_users: list[str] = Field(default_factory=list)
    victim_hosts: list[str] = Field(default_factory=list)
    pivot_hosts: list[str] = Field(default_factory=list)
    stages: list[TruthStage] = Field(default_factory=list)
    decoys: list[TruthDecoy] = Field(default_factory=list)
    gaps: list[TruthGap] = Field(default_factory=list)
    files: dict[str, int] = Field(default_factory=dict)  # file -> line count
    n_events_rendered: int = 0
    t_start: datetime
    t_end: datetime


# --------------------------------------------------------------------------- API envelopes
class Funnel(_M):
    events: int = 0
    signals: int = 0
    linked_signals: int = 0
    incidents: int = 0
    watchlist: int = 0


class CaseSummary(_M):
    case_id: str
    name: str
    source: CaseSource
    status: CaseStatus
    pipeline_version: str
    contract_version: str = CONTRACT_VERSION
    scenario_seed: int | None = None
    scenario_params: ScenarioParams | None = None
    funnel: Funnel
    parse_report: ParseReport | None = None
    error: str | None = None


class CaseCreated(_M):
    case_id: str


class ScenarioRequest(_M):
    seed: int = Field(ge=0, le=2**31 - 1)
    params: ScenarioParams = Field(default_factory=ScenarioParams)


class IncidentList(_M):
    case_id: str
    incidents: list[Incident]


class ScoreBreakdownResponse(_M):
    breakdown: ScoreBreakdown


class IncidentDetail(_M):
    incident: Incident
    claims: list[Claim]
    score_breakdown: ScoreBreakdown
    dismissals: list[Dismissal] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)


class Suspect(_M):
    entity: Entity
    role: EntityRole
    chain_score: float
    risk_ledger: list[tuple[datetime, float]] = Field(default_factory=list)  # (t, cumulative risk)
    distinct_stages: int = 0
    signal_ids: list[str] = Field(default_factory=list)
    actor_cluster: ActorCluster | None = None


class SuspectList(_M):
    case_id: str
    suspects: list[Suspect]


class DismissalList(_M):
    case_id: str
    dismissals: list[Dismissal]


class NaiveAlert(_M):
    signal_id: str
    detector: str
    title: str
    entity: str
    t: datetime
    severity: float


class NaiveView(_M):
    case_id: str
    alerts: list[NaiveAlert]


class EventsPage(_M):
    case_id: str
    events: list[Event]
    next_cursor: str | None = None
    total: int


class EventContext(_M):
    event: Event
    before: list[str]  # raw lines
    after: list[str]
    line_no: int
    file_name: str
    producing_signals: list[str] = Field(default_factory=list)


class EntityProfile(_M):
    entity: Entity
    baseline: dict[str, Any] = Field(default_factory=dict)
    observed: dict[str, Any] = Field(default_factory=dict)
    event_count: int = 0


class MatchResult(_M):
    kind: str
    truth: list[str]
    predicted: list[str]
    hits: list[str]
    misses: list[str]
    false_positives: list[str]


class Scorecard(_M):
    attacker_ip_recall: float | None = None
    compromised_user_recall: float | None = None
    false_suspect_count: int = 0
    stage_order_accuracy: float | None = None  # Kendall tau mapped to [0,1]
    cluster_purity: float | None = None
    alert_compression: float | None = None  # signals / incidents
    gap_recall: float | None = None
    runtime_ms: int | None = None
    baselines: dict[str, dict[str, float]] = Field(default_factory=dict)  # B0 / B1 comparison


class RevealResponse(_M):
    case_id: str
    truth: GroundTruth
    matches: list[MatchResult]
    scorecard: Scorecard


class EvalReport(_M):
    generated_at: datetime
    pipeline_version: str
    n_scenarios: int
    seeds: list[int] = Field(default_factory=list)
    metrics: dict[str, dict[str, float]] = Field(default_factory=dict)  # system -> metric -> value (B0/B1/B2)
    by_tier: dict[str, dict[str, float]] = Field(default_factory=dict)
    by_template: dict[str, dict[str, float]] = Field(default_factory=dict)
    misses: list[dict[str, Any]] = Field(default_factory=list)


class ProgressEvent(_M):
    case_id: str
    stage: str  # ingest | normalize | baseline | detect | correlate | reconstruct | score | explain | done | error
    counts: dict[str, int] = Field(default_factory=dict)
    message: str | None = None


class Health(_M):
    status: str = "ok"
    contract_version: str = CONTRACT_VERSION
    pipeline_version: str
