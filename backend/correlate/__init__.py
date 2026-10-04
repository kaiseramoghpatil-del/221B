"""Predicate correlation (prerequisite/consequence model, Ning-Cui-Reeves style) + the locked admission rule.

Forward-chaining over signals in time order:
  * A signal's `requires` are matched against predicate instances that are *held by the attacker so far*.
    A match creates a PREDICATE link A -> B carrying the satisfying instance (`via`): the edge explains itself.
  * A signal's `produces` become attacker-held only if it is an anchor (initial-access detector) or at least one
    of its requirements was satisfied. A routine engineer hop therefore does NOT propagate access: consequences
    only hold when prerequisites hold.
  * If a signal's prerequisites are unsatisfied but it shares an attacker-side identity (compromised user, or an
    IP already in a chain) with an active chain, it is bridged with an INFERRED link and a GAP is recorded
    (the predicate that should have been logged but was not). Inferred links never count toward admission.
  * Credential-attack signals (RECON: brute force / spray) are linked to the access they enabled when they share
    the source IP or the target account.

Admission (locked): an Incident requires >= 2 distinct attack stages connected by valid correlation predicates.
No bypass. Single-stage clusters become Watchlist items; a confirmed-impact single-stage finding (successful
privilege escalation or exfiltration) is a HIGH-priority Watchlist item.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from backend.core.ids import short
from backend.normalize import is_internal
from backend.core.models import (Gap, Incident, IncidentStatus, Link, LinkKind, PredicateInstance, PredicateName as PN,
                                 Signal, Stage, STAGE_ORDER, WatchlistPriority)

TIME_TOLERANCE = timedelta(seconds=120)  # producer may be stamped slightly after consumer (clock skew between sources)
DEFAULT_VALIDITY = timedelta(hours=24)  # validity of a non-session-scoped predicate
SESSION_GRACE = timedelta(minutes=30)
BRIDGE_WINDOW = timedelta(hours=12)
BRIDGE_MIN_STRENGTH = 0.2  # routine/informational signals are never bridged into a chain
WEAK_ANCHOR_CONFIRM = 0.40  # a weak anchor (new source, normal hours) is confirmed only by a strong dependent signal
RECON_LINK_WINDOW = timedelta(hours=24)
WATCHLIST_MIN_STRENGTH = 0.32  # 'worth a look on its own'
IMPACT_DETECTORS = {"D06", "D10"}


@dataclass
class Held:
    inst: PredicateInstance
    signal_id: str
    inferred: bool
    valid_until: object  # datetime
    weak: bool = False  # from an unconfirmed weak anchor


@dataclass
class Correlation:
    links: list[Link]
    incidents: list[Incident]
    watchlist: list[Incident]
    low_signal: list[str]  # signal ids below watchlist threshold (counted, not listed)
    component_of: dict[str, str]  # signal id -> incident/watchlist id
    active_signals: set[str] = field(default_factory=set)  # signals whose consequences became attacker-held
    gaps_by_signal: dict[str, Gap] = field(default_factory=dict)
    ambiguous: dict[str, list[str]] = field(default_factory=dict)  # signal id -> candidate accounts it could belong to


class _UF:
    def __init__(self, items):
        self.p = {i: i for i in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def strength(s: Signal) -> float:
    return min(1.0, s.severity * s.confidence * (0.5 + 0.5 * s.rarity) * s.criticality_mult)


def _matches(held: Held, req: PredicateInstance, t, sessions_end: dict) -> bool:
    if held.inst.name != req.name:
        return False
    for k, v in req.args.items():
        if k == "via":
            continue
        if held.inst.args.get(k) != v:
            return False
    pt = held.inst.t
    if pt is not None and t is not None and pt > t + TIME_TOLERANCE:
        return False
    return t is None or t <= held.valid_until


def _identities(s: Signal) -> set[str]:
    """Attacker-side identities usable for gap bridging: accounts and *external* IPs (internal IPs are shared infra)."""
    return {e for e in s.entities if e.startswith("user:") or (e.startswith("ip:") and not is_internal(e[3:]))}


def correlate(signals: list[Signal], sessions_end: dict[str, object]) -> Correlation:
    sigs = sorted(signals, key=lambda s: (s.t_start, s.detector, s.id))
    by_id = {s.id: s for s in sigs}
    held: list[Held] = []
    links: list[Link] = []
    active: set[str] = set()
    inferred_sig: set[str] = set()
    gaps: dict[str, Gap] = {}
    chain_identity: dict[str, list[tuple[object, str]]] = defaultdict(list)  # identity -> [(t, signal id)] of active signals
    recon: list[Signal] = [s for s in sigs if s.stage_hint is Stage.RECON]
    ambiguous: dict[str, list[str]] = {}
    running = _UF([s.id for s in sigs])  # chains as they form, for disambiguating host-only requirements
    size: dict[str, int] = defaultdict(lambda: 1)

    def chain_size(sid: str) -> int:
        return size[running.find(sid)]

    def absorb(new_links: list[Link]) -> None:
        for l in new_links:
            ra, rb = running.find(l.signal_a), running.find(l.signal_b)
            if ra != rb:
                total = size[ra] + size[rb]
                running.union(ra, rb)
                size[running.find(l.signal_a)] = total

    for s in sigs:
        satisfied = False
        strong = strength(s) >= WEAK_ANCHOR_CONFIRM and not s.features.get("informational")
        for req in s.requires:
            every = [h for h in held if _matches(h, req, s.t_start, sessions_end)]
            cands = [h for h in every if not h.weak or strong]
            if not cands:
                continue
            if "user" not in req.args and len({h.inst.args.get("user") for h in every}) > 1:
                # host-level requirement (e.g. a network sweep from bastion-01) while several accounts hold access
                # there: genuinely ambiguous - do not guess which chain it belongs to
                ambiguous.setdefault(s.id, sorted({str(h.inst.args.get("user")) for h in every}))
                continue
            # several chains may hold e.g. has_access(host=bastion-01): prefer the most developed chain, then recency
            best = max(cands, key=lambda h: (chain_size(h.signal_id), not h.inferred, h.inst.t or s.t_start))
            if best.signal_id == s.id:
                continue
            satisfied = True
            n0 = len(links)
            if best.weak:  # retroactive confirmation of a weak anchor
                for h in held:
                    if h.signal_id == best.signal_id:
                        h.weak = False
                _activate(by_id[best.signal_id], active, chain_identity, recon, links)
            links.append(Link(signal_a=best.signal_id, signal_b=s.id, kind=LinkKind.predicate, via=best.inst,
                              reason=f"{req.name.value} established by {by_id[best.signal_id].detector}", weight=1.0))
            absorb(links[n0:])
        anchor = bool(s.features.get("anchor"))
        weak_anchor = bool(s.features.get("weak_anchor"))
        bridged = False
        if not satisfied and not anchor and s.requires and strength(s) >= BRIDGE_MIN_STRENGTH and not s.features.get("informational"):
            # unsatisfied prerequisite: bridge to an active chain via a shared attacker-side identity
            for ident in sorted(_identities(s)):
                prior = [(t, sid) for t, sid in chain_identity.get(ident, []) if timedelta(0) <= s.t_start - t <= BRIDGE_WINDOW]
                if prior:
                    t_p, sid_p = max(prior)
                    links.append(Link(signal_a=sid_p, signal_b=s.id, kind=LinkKind.soft, via=None,
                                      reason=f"inferred_via_gap: shares {ident} with an active chain", weight=0.5))
                    gaps[s.id] = Gap(id=short("G", s.id), kind="unsatisfied_prerequisite",
                                     description=(f"{s.detector} implies {s.requires[0].name.value}"
                                                  f"({', '.join(f'{k}={v}' for k, v in s.requires[0].args.items() if k != 'session')})"
                                                  " but no logged event establishes it - possible missing log source or unlogged step"),
                                     host=s.requires[0].args.get("host"), t_start=t_p, t_end=s.t_start, missing_predicate=s.requires[0])
                    bridged = True
                    inferred_sig.add(s.id)
                    break
        if anchor or satisfied or bridged or weak_anchor:
            for p in s.produces:
                sess = p.args.get("session")
                until = sessions_end.get(sess) if sess else None
                until = (until + SESSION_GRACE) if until else (s.t_end + DEFAULT_VALIDITY)
                held.append(Held(inst=p, signal_id=s.id, inferred=bridged and not satisfied, valid_until=until,
                                 weak=weak_anchor and not (anchor or satisfied or bridged)))
            if anchor or satisfied or bridged:
                n0 = len(links)
                _activate(s, active, chain_identity, recon, links)
                absorb(links[n0:])

    # ---- clustering: predicate links + inferred gap bridges; admission uses predicate links only
    ids = [s.id for s in sigs]
    uf_all, uf_pred = _UF(ids), _UF(ids)
    for l in links:
        if l.kind is LinkKind.predicate or l.reason.startswith("inferred_via_gap"):
            uf_all.union(l.signal_a, l.signal_b)
        if l.kind is LinkKind.predicate:
            uf_pred.union(l.signal_a, l.signal_b)
    comps: dict[str, list[Signal]] = defaultdict(list)
    for s in sigs:
        comps[uf_all.find(s.id)].append(s)
    outgoing = defaultdict(int)
    for l in links:
        if l.kind is LinkKind.predicate:
            outgoing[l.signal_a] += 1

    incidents: list[Incident] = []
    watch: list[Incident] = []
    low: list[str] = []
    component_of: dict[str, str] = {}
    for root, members in comps.items():
        pred_groups: dict[str, set[Stage]] = defaultdict(set)
        for m in members:
            pred_groups[uf_pred.find(m.id)].add(m.stage_hint)
        admitted = any(len(st) >= 2 for st in pred_groups.values())
        linked = len(members) > 1
        score, kappas = _score(members, outgoing, linked, admitted)
        stages = sorted({m.stage_hint for m in members}, key=lambda x: STAGE_ORDER[x])
        ents = sorted({e for m in members for e in m.entities})
        t0, t1 = min(m.t_start for m in members), max(m.t_end for m in members)
        inc_gaps = [gaps[m.id] for m in members if m.id in gaps]
        if admitted:
            iid = short("INC", root)
            inc = Incident(id=iid, title=f"Multi-stage intrusion: {stages[0].value} -> {stages[-1].value}", status=IncidentStatus.incident,
                           signal_ids=[m.id for m in members], entities=ents, t_start=t0, t_end=t1, stages_covered=stages,
                           score=score, confidence=_confidence(members, links, inc_gaps), gaps=inc_gaps)
            incidents.append(inc)
        else:
            impact = any(m.features.get("confirmed_impact") for m in members)
            if max(strength(m) for m in members) < WATCHLIST_MIN_STRENGTH and not impact:
                low.extend(m.id for m in members)
                continue
            iid = short("WL", root)
            lead = max(members, key=strength)
            reason = ("single-stage finding" + (" with confirmed impact - high priority, but no correlated second stage" if impact else
                                                 "; no second attack stage is connected to it by a correlation predicate"))
            inc = Incident(id=iid, title=lead.title, status=IncidentStatus.watchlist, signal_ids=[m.id for m in members], entities=ents,
                           t_start=t0, t_end=t1, stages_covered=stages,
                           watchlist_priority=WatchlistPriority.high if impact else WatchlistPriority.normal,
                           watchlist_reason=reason, score=score, confidence=min(0.95, lead.confidence), gaps=inc_gaps)
            watch.append(inc)
        for m in members:
            component_of[m.id] = iid
    incidents.sort(key=lambda i: -i.score)
    watch.sort(key=lambda i: (i.watchlist_priority != WatchlistPriority.high, -i.score))
    return Correlation(links=links, incidents=incidents, watchlist=watch, low_signal=low, component_of=component_of,
                       active_signals=active, gaps_by_signal=gaps, ambiguous=ambiguous)


def _activate(s: Signal, active: set, chain_identity: dict, recon: list[Signal], links: list[Link]) -> None:
    if s.id in active:
        return
    active.add(s.id)
    for ident in _identities(s):
        chain_identity[ident].append((s.t_start, s.id))
    if s.stage_hint is Stage.INITIAL_ACCESS:
        _link_recon(s, recon, links)


def _link_recon(access: Signal, recon: list[Signal], links: list[Link]) -> None:
    """Credential attacks that preceded (and plausibly enabled) this access: shared source IP or targeted account."""
    acc_ips = (set(access.features.get("consumes_ips") or []) | {access.features.get("src_ip")}
               | {e[3:] for e in access.entities if e.startswith("ip:") and not is_internal(e[3:])}) - {None}
    acc_users = {e[5:] for e in access.entities if e.startswith("user:")}
    via = next((p for p in access.produces if p.name is PN.credential_compromised), None) or (access.produces[0] if access.produces else None)
    for r in recon:
        if not (timedelta(0) <= access.t_start - r.t_end <= RECON_LINK_WINDOW or r.t_start <= access.t_start <= r.t_end):
            continue
        r_ips = (set(r.features.get("src_ips") or []) | {r.features.get("src_ip")}) - {None}
        # account-based linking only for attacks *focused* on one account (a broad brute force that happened to
        # include this username is not evidence that it enabled this access)
        r_users = {r.features.get("target_user")} - {None}
        if r.features.get("mode") == "slow":
            r_users.add(r.features.get("top_user"))
        shared = (acc_ips & r_ips) or (acc_users & r_users)
        if shared:
            links.append(Link(signal_a=r.id, signal_b=access.id, kind=LinkKind.predicate, via=via,
                              reason=f"credential attack preceded the access (shared {', '.join(sorted(shared))[:80]})", weight=0.8))


def _score(members: list[Signal], outgoing: dict, linked: bool, admitted: bool) -> tuple[float, dict]:
    """Consequence weighting: a signal counts fully only if something followed from it (or it is impact)."""
    prod = 1.0
    kappas = {}
    for m in members:
        if not linked:
            k = 0.2 if m.detector not in IMPACT_DETECTORS else 0.6
        elif outgoing.get(m.id) or m.detector == "D10":
            k = 1.0
        else:
            k = 0.6
        kappas[m.id] = k
        prod *= 1 - strength(m) * k
    score = 1 - prod
    if admitted:
        n_stages = len({m.stage_hint for m in members})
        score += 0.03 * max(0, n_stages - 2)
    return round(min(1.0, score), 4), kappas


def _confidence(members: list[Signal], links: list[Link], gaps: list[Gap]) -> float:
    ids = {m.id for m in members}
    mine = [l for l in links if l.signal_b in ids]
    pred = sum(1 for l in mine if l.kind is LinkKind.predicate)
    completeness = pred / max(1, len(mine))
    mean_conf = sum(m.confidence for m in members) / len(members)
    return round(min(0.99, 0.5 * completeness + 0.4 * mean_conf + 0.1 * (1.0 if not gaps else 0.5)), 3)
