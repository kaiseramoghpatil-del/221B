"""Host-activity detectors: D06 privilege escalation, D07b discovery commands, D08 lateral movement,
D09 staging, D11 persistence / defence evasion."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from backend.baseline import is_archive_cmd
from backend.core.models import Action, Event, Outcome, PredicateName as PN, RuleMeta, Stage
from backend.normalize import is_internal

from .base import DetectCtx, Detector, P, mk_signal

SHELL_TOKENS = ("/bin/bash", "/bin/sh", "/bin/zsh", "sudo -i", "su -", "/usr/bin/bash")
RECON_CMDS = ("whoami", "id", "uname -a", "cat /etc/passwd", "cat /etc/shadow", "ss -tulpn", "netstat -an", "ip neigh",
              "arp -a", "nmap", "hostname", "last", "w", "cat /etc/hosts", "ifconfig", "ip a")
BIG_READ = 500_000_000


def _access_req(ctx: DetectCtx, e: Event):
    """What an action on a host presupposes: access (session-scoped when we know the session) or privilege there."""
    s = ctx.session(e)
    return [P(PN.has_access, e.ts_utc, user=e.user, host=e.host, session=s),
            P(PN.privileged, e.ts_utc, user=e.user, host=e.host, session=s)]


# ----------------------------------------------------------------------------- D06
D06 = Detector("D06", "Privilege escalation (first-time root on host)", Stage.PRIV_ESC, RuleMeta(
    level="high", tags=["attack.privilege_escalation", "attack.t1548.003"],
    falsepositives=["New on-call engineer granted sudo", "Admin working on a host for the first time"],
    references=["MITRE ATT&CK T1548.003 Sudo and Sudo Caching"]), run=lambda ctx: _d06(ctx))


def _d06(ctx: DetectCtx):
    b = ctx.b
    out = []
    for e in ctx.nc.events:
        if not (e.action in (Action.sudo, Action.su) and e.outcome is Outcome.success and e.user and e.host):
            continue
        novel = b.novel(b.fs_user_host_sudo, (e.user, e.host), e.ts_utc)
        shell = any(t in (e.object or "") for t in SHELL_TOKENS) or e.action is Action.su
        if not novel:
            continue
        s = ctx.session(e)
        history = b.user_sudo_count[e.user]
        out.append(mk_signal(
            D06, e.id, [e], entities=[f"user:{e.user}", f"host:{e.host}"],
            severity=(0.8 if shell else 0.4) - (0.2 if history > 20 else 0.0), confidence=0.8, rarity=0.85, crit=ctx.crit(e.host),
            template="{user} ran '{cmd}' as {target} on {host} - first time this account used root there" + (" (interactive root shell)" if shell else ""),
            params={"user": e.user, "cmd": e.object or e.action.value, "target": e.attrs.get("target_user", "root"), "host": e.host},
            requires=[P(PN.has_access, e.ts_utc, user=e.user, host=e.host, session=s)],
            produces=[P(PN.privileged, e.ts_utc, user=e.user, host=e.host, session=s)],
            features={"session": s, "shell": shell, "prior_sudo_total": history, "confirmed_impact": shell}))
    return out


# ----------------------------------------------------------------------------- D07b
D07B = Detector("D07b", "Host reconnaissance commands", Stage.EXECUTION, RuleMeta(
    level="medium", tags=["attack.discovery", "attack.t1033", "attack.t1082"],
    falsepositives=["Admin troubleshooting identity or network config"],
    references=["MITRE ATT&CK T1033 System Owner/User Discovery", "T1082 System Information Discovery"]), run=lambda ctx: _d07b(ctx))


def _is_recon(cmd: str | None) -> bool:
    c = (cmd or "").strip()
    return any(c == r or c.startswith(r + " ") for r in RECON_CMDS)


def _d07b(ctx: DetectCtx):
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for e in ctx.nc.events:
        if e.action is Action.proc_exec and e.user and e.host and _is_recon(e.object):
            groups[(e.user, e.host, ctx.session(e))].append(e)
    out = []
    for (user, host, s), evs in sorted(groups.items(), key=lambda kv: kv[1][0].ts_utc):
        cluster: list[Event] = []
        for e in evs + [None]:
            if e is not None and (not cluster or e.ts_utc - cluster[-1].ts_utc <= timedelta(minutes=30)):
                cluster.append(e)
                continue
            if len({c.object for c in cluster}) >= 3:
                out.append(mk_signal(
                    D07B, cluster[0].id, cluster, entities=[f"user:{user}", f"host:{host}"], severity=0.45, confidence=0.75,
                    rarity=0.7, crit=ctx.crit(host),
                    template="{user} ran {n} reconnaissance commands on {host} within {mins} min: {cmds}",
                    params={"user": user, "host": host, "n": len(cluster),
                            "mins": max(1, int((cluster[-1].ts_utc - cluster[0].ts_utc).total_seconds() // 60)),
                            "cmds": ", ".join(dict.fromkeys(c.object for c in cluster))},
                    requires=_access_req(ctx, cluster[0]), produces=[P(PN.foothold, cluster[0].ts_utc, host=host, user=user, session=s)],
                    features={"session": s, "commands": list(dict.fromkeys(c.object for c in cluster))}))
            cluster = [e] if e is not None else []
    return out


# ----------------------------------------------------------------------------- D08
D08 = Detector("D08", "Internal hop to another host", Stage.LATERAL_MOVEMENT, RuleMeta(
    level="medium", tags=["attack.lateral_movement", "attack.t1021.004"],
    falsepositives=["Engineers routinely jump bastion -> app servers (non-novel hops are informational only)"],
    references=["MITRE ATT&CK T1021.004 Remote Services: SSH"]), run=lambda ctx: _d08(ctx))


def _d08(ctx: DetectCtx):
    b, nc = ctx.b, ctx.nc
    out = []
    for e in nc.events:
        if not (e.action is Action.login and e.outcome is Outcome.success and e.user and e.host and is_internal(e.src_ip)):
            continue
        src_host = nc.ip_to_host.get(e.src_ip)
        s = ctx.session(e)
        parent = nc.sessions[s].parent if s else None
        novel = b.novel(b.fs_user_host, (e.user, e.host), e.ts_utc)
        req = [P(PN.has_access, e.ts_utc, user=e.user, host=src_host, session=parent)] if src_host else []
        out.append(mk_signal(
            D08, e.id, [e], entities=[f"user:{e.user}", f"host:{e.host}"] + ([f"host:{src_host}"] if src_host else []),
            severity=0.4 if novel else 0.15, confidence=0.8, rarity=0.85 if novel else 0.2, crit=ctx.crit(e.host),
            template="{user} hopped from {src} to {host}" + (" - first time this account ever reached {host}" if novel else ""),
            params={"user": e.user, "src": src_host or e.src_ip, "host": e.host},
            requires=req, produces=[P(PN.has_access, e.ts_utc, user=e.user, host=e.host, session=s, via=src_host or e.src_ip)],
            features={"session": s, "parent_session": parent, "novel_destination": novel, "src_host": src_host, "informational": not novel}))
    return out


# ----------------------------------------------------------------------------- D09
D09 = Detector("D09", "Data staging (archive / bulk read)", Stage.COLLECTION, RuleMeta(
    level="high", tags=["attack.collection", "attack.t1074.001", "attack.t1560.001"],
    falsepositives=["Scheduled backup jobs (periodic, same account - suppressed by history)"],
    references=["MITRE ATT&CK T1074 Data Staged", "T1560.001 Archive via Utility"]), run=lambda ctx: _d09(ctx))


def _d09(ctx: DetectCtx):
    b = ctx.b
    out = []
    for e in ctx.nc.events:
        if not (e.user and e.host):
            continue
        archive = e.action is Action.proc_exec and is_archive_cmd(e.object) and b.novel(b.fs_user_host_archive, (e.user, e.host), e.ts_utc)
        bulk = e.action is Action.file_read and (e.bytes_out or 0) >= BIG_READ
        if not (archive or bulk):
            continue
        out.append(mk_signal(
            D09, e.id, [e], entities=[f"user:{e.user}", f"host:{e.host}"], severity=0.6 if archive else 0.65, confidence=0.75,
            rarity=0.85, crit=ctx.crit(e.host),
            template=("{user} archived data on {host}: '{obj}'" if archive else "{user} read {gb} GB from {obj} on {host}"),
            params={"user": e.user, "host": e.host, "obj": e.object, "gb": round((e.bytes_out or 0) / 1e9, 2)},
            requires=_access_req(ctx, e), produces=[P(PN.staged, e.ts_utc, host=e.host, resource=e.object)],
            features={"session": ctx.session(e), "kind": "archive" if archive else "bulk_read", "bytes": e.bytes_out}))
    return out


# ----------------------------------------------------------------------------- D11
D11 = Detector("D11", "Persistence / defence evasion", Stage.PERSISTENCE, RuleMeta(
    level="high", tags=["attack.persistence", "attack.t1098.004", "attack.t1053.003", "attack.t1136.001", "attack.t1070.002"],
    falsepositives=["Admin provisioning a new hire (account creation after long sudo history)", "Config management adding keys"],
    references=["MITRE ATT&CK T1098.004 SSH Authorized Keys", "T1136.001 Create Local Account", "T1070.002 Clear Linux Logs"]),
    run=lambda ctx: _d11(ctx))

_MECH = {Action.key_add: ("ssh_authorized_key", 0.65), Action.cron_add: ("cron_job", 0.5), Action.log_clear: ("log_clearing", 0.7),
         Action.useradd: ("new_account", 0.35), Action.group_add: ("group_membership", 0.3)}


def _d11(ctx: DetectCtx):
    out = []
    last_sudo: dict[str, Event] = {}
    for e in ctx.nc.events:
        if e.action is Action.sudo and e.host:
            last_sudo[e.host] = e
        if e.action not in _MECH:
            continue
        mech, sev = _MECH[e.action]
        actor = e.user
        if actor is None and e.host in last_sudo and e.ts_utc - last_sudo[e.host].ts_utc <= timedelta(minutes=2):
            actor = last_sudo[e.host].user  # account creation is logged without the actor; attribute to the preceding sudo
        admin_like = actor is not None and ctx.b.user_sudo_count[actor] > 20
        if admin_like and e.action in (Action.useradd, Action.group_add):
            sev = 0.12
        req = [P(PN.has_access, e.ts_utc, user=actor, host=e.host, session=ctx.session(e)),
               P(PN.privileged, e.ts_utc, user=actor, host=e.host, session=ctx.session(e))] if actor else \
            [P(PN.privileged, e.ts_utc, host=e.host)]
        out.append(mk_signal(
            D11, e.id, [e], entities=([f"user:{actor}"] if actor else []) + [f"host:{e.host}"], severity=sev, confidence=0.8,
            rarity=0.8, crit=ctx.crit(e.host), title="Defence evasion: logs cleared" if e.action is Action.log_clear else None,
            template="{actor} {what} on {host}" + (" (actor has a long admin history)" if admin_like else ""),
            params={"actor": actor or "unknown account", "host": e.host,
                    "what": {"ssh_authorized_key": f"added an SSH key to {e.object}", "cron_job": f"added a cron job {e.object}",
                             "log_clearing": f"cleared {e.object}", "new_account": f"created account '{e.object}'",
                             "group_membership": f"changed group membership '{e.object}'"}[mech]},
            requires=req, produces=[P(PN.persisted, e.ts_utc, host=e.host, mechanism=mech)],
            features={"session": ctx.session(e), "mechanism": mech, "actor": actor, "admin_like_actor": admin_like}))
    return out


DETECTORS = [D06, D07B, D08, D09, D11]
