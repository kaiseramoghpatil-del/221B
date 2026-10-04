import type { Stage } from "../api/client";

const dtf = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
});
const tf = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" });
const nf = new Intl.NumberFormat("en-US");
const pf = new Intl.NumberFormat("en-US", { style: "percent", maximumFractionDigits: 0 });

export const fmtDateTime = (iso: string) => `${dtf.format(new Date(iso))} UTC`;
export const fmtTime = (iso: string | number) => tf.format(new Date(iso));
export const fmtNum = (n: number) => nf.format(n);
export const fmtPct = (x: number) => pf.format(x);

export function fmtDuration(ms: number): string {
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const r = m % 60;
  if (h < 48) return r ? `${h} h ${r} min` : `${h} h`;
  return `${Math.round(h / 24)} days`;
}

export function fmtBytes(gb: number): string {
  return gb >= 1 ? `${gb.toFixed(1)} GB` : `${Math.round(gb * 1000)} MB`;
}

/** Plain-English stage names first; ATT&CK tactic names as the secondary tag. */
export const STAGE: Record<Stage, { short: string; plain: string; tactic: string }> = {
  RECON: { short: "Guessing", plain: "Password guessing", tactic: "Credential Access" },
  INITIAL_ACCESS: { short: "Entry", plain: "Break-in", tactic: "Initial Access" },
  EXECUTION: { short: "Foothold", plain: "Looking around", tactic: "Execution / Discovery" },
  PERSISTENCE: { short: "Persistence", plain: "Staying in", tactic: "Persistence" },
  PRIV_ESC: { short: "Root", plain: "Becoming root", tactic: "Privilege Escalation" },
  DISCOVERY: { short: "Scan", plain: "Mapping the network", tactic: "Discovery" },
  LATERAL_MOVEMENT: { short: "Lateral", plain: "Moving between hosts", tactic: "Lateral Movement" },
  COLLECTION: { short: "Staging", plain: "Gathering data", tactic: "Collection" },
  EXFILTRATION: { short: "Exfil", plain: "Taking data out", tactic: "Exfiltration" },
};

export const ROLE: Record<string, string> = {
  attacker_infra: "Attacker infrastructure",
  compromised_account: "Compromised account",
  pivot_host: "Used as a stepping stone",
  victim_host: "Data taken from here",
  noisy_benign: "Noisy, not the intruder",
  unknown: "Watch",
};

export const entityLabel = (id: string) => id.split(":").slice(1).join(":");
export const entityKind = (id: string) => id.split(":")[0];
