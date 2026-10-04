import type { AttackGraph, AttackStep, Claim, Stage } from "../api/client";
import { entityKind, entityLabel } from "./format";

/** Shared geometry for Exhibit A (attack path) and Exhibit B (session timeline): one row per place, one column per stage. */
export type Row = { id: string; label: string; kind: "ip" | "host"; role: string; depth: number };
export type Cell = { step: AttackStep; row: number; col: number; text: string; claim?: Claim; terminalRow?: number };
export type Board = { rows: Row[]; cols: Stage[]; cells: Cell[] };

const gb = (x: unknown) => (typeof x === "number" ? `${x < 1 ? Math.round(x * 1000) + " MB" : x.toFixed(1) + " GB"}` : "");

function chipText(step: AttackStep, claim?: Claim): string {
  // short on purpose: the column header already names the stage; the full sentence lives in the findings
  const f = (claim?.facts ?? {}) as Record<string, unknown>;
  switch (step.stage) {
    case "RECON":
      return `${f.n ?? f.attempts ?? step.summary_count ?? ""} fails`.trim();
    case "INITIAL_ACCESS":
      return String(f.user ?? entityLabel(step.actor_entity ?? ""));
    case "EXECUTION":
      return `${f.n ?? ""} commands`.trim();
    case "DISCOVERY":
      return `${f.n ?? ""} ports`.trim();
    case "PRIV_ESC":
      return String(f.cmd ?? "").includes("bash") ? "root shell" : "root";
    case "PERSISTENCE": {
      const w = String(f.what ?? "");
      return w.startsWith("added an SSH key") ? "SSH key" : w.startsWith("cleared") ? "logs wiped" : w.startsWith("created account") ? "new account" : w.startsWith("added a cron") ? "cron job" : "persistence";
    }
    case "LATERAL_MOVEMENT":
      return `← ${f.src ?? "?"}`;
    case "COLLECTION":
      return f.gb ? gb(f.gb) : "archive";
    case "EXFILTRATION":
      return f.gb ? `${gb(f.gb)} out` : "data out";
    default:
      return step.stage;
  }
}

export function buildBoard(steps: AttackStep[], graph: AttackGraph | null, claims: Claim[]): Board {
  const roleOf = new Map((graph?.nodes ?? []).map((n) => [n.id, n.role as string]));
  const claimOf = new Map(claims.filter((c) => c.step_id).map((c) => [c.step_id!, c]));
  const exfilDst = new Map<string, string>();
  for (const e of graph?.edges ?? []) {
    if (entityKind(e.target) === "ip" && entityKind(e.source) === "host") exfilDst.set(e.source, e.target);
  }

  const placeOf = (s: AttackStep): string | null => {
    if (s.stage === "RECON") return s.actor_entity ?? null;
    return s.target_entity ?? s.actor_entity ?? null;
  };

  const ipRows: string[] = [];
  const hostRows: string[] = [];
  const depth = new Map<string, number>();
  for (const s of steps) {
    const p = placeOf(s);
    if (!p) continue;
    if (entityKind(p) === "ip") {
      if (!ipRows.includes(p)) ipRows.push(p);
    } else if (!hostRows.includes(p)) {
      hostRows.push(p);
      const claim = claimOf.get(s.id);
      const src = (claim?.facts as Record<string, unknown> | undefined)?.src;
      const parent = typeof src === "string" ? `host:${src}` : null;
      depth.set(p, parent && depth.has(parent) ? (depth.get(parent) ?? 0) + 1 : 0);
    }
    if (s.stage === "INITIAL_ACCESS" && s.actor_entity && entityKind(s.actor_entity) === "ip" && !ipRows.includes(s.actor_entity)) {
      ipRows.push(s.actor_entity);
    }
  }
  for (const dst of exfilDst.values()) if (!ipRows.includes(dst)) ipRows.push(dst);

  const rows: Row[] = [
    ...ipRows.map((id) => ({ id, label: entityLabel(id), kind: "ip" as const, role: roleOf.get(id) ?? "attacker_infra", depth: 0 })),
    ...hostRows.map((id) => ({ id, label: entityLabel(id), kind: "host" as const, role: roleOf.get(id) ?? "unknown", depth: depth.get(id) ?? 0 })),
  ];
  const rowIdx = new Map(rows.map((r, i) => [r.id, i]));
  const cols: Stage[] = [];
  for (const s of steps) if (!cols.includes(s.stage)) cols.push(s.stage);

  const cells: Cell[] = [];
  for (const s of steps) {
    const p = placeOf(s);
    if (!p || !rowIdx.has(p)) continue;
    const claim = claimOf.get(s.id);
    const cell: Cell = { step: s, row: rowIdx.get(p)!, col: cols.indexOf(s.stage), text: chipText(s, claim), claim };
    if (s.stage === "EXFILTRATION" && s.target_entity && exfilDst.has(s.target_entity)) {
      cell.terminalRow = rowIdx.get(exfilDst.get(s.target_entity)!);
    }
    cells.push(cell);
  }
  return { rows, cols, cells };
}
