/**
 * Start-screen replay of the demo case's STORED results (src/data/demoCase.json, written by `python -m eval.demo_snapshot`).
 * Nothing here analyses logs: it plays back numbers and lines the pipeline already produced, in about 3 seconds.
 */
import { useEffect, useRef, useState } from "react";
import demo from "../data/demoCase.json";

export { demo };
export type Step = (typeof demo.steps)[number];

const REPLAY_MS = 3000;
const STEP_FROM = 0.35;
const STEP_EVERY = 0.055;

/** 0 → 1 over the replay; jumps straight to 1 when the viewer prefers reduced motion. */
export function useReplay() {
  const [t, setT] = useState(0);
  const [run, setRun] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setT(1);
      return;
    }
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const v = Math.min(1, (now - t0) / REPLAY_MS);
      setT(v);
      if (v < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [run]);
  return { t, replay: () => setRun((r) => r + 1) };
}

export const seg = (t: number, a: number, b: number) => Math.max(0, Math.min(1, (t - a) / (b - a)));
const ease = (x: number) => 1 - Math.pow(1 - x, 3);
export const stepsShown = (t: number) => (t < STEP_FROM ? 0 : Math.min(demo.steps.length, 1 + Math.floor((t - STEP_FROM) / STEP_EVERY)));
export const hhmm = (iso: string) => iso.slice(11, 16);
export const fmt = (n: number) => n.toLocaleString("en-US");

export const STAGE_SHORT: Record<string, string> = {
  RECON: "Recon",
  INITIAL_ACCESS: "Entry",
  EXECUTION: "Exec",
  DISCOVERY: "Scan",
  PRIV_ESC: "Root",
  PERSISTENCE: "Key",
  LATERAL_MOVEMENT: "Hop",
  COLLECTION: "Stage",
  EXFILTRATION: "Exfil",
};
export const STAGE_LONG: Record<string, string> = {
  RECON: "Password spray",
  INITIAL_ACCESS: "Logged in",
  EXECUTION: "Recon commands",
  DISCOVERY: "Internal scan",
  PRIV_ESC: "Root shell",
  PERSISTENCE: "SSH key planted",
  LATERAL_MOVEMENT: "Hopped",
  COLLECTION: "Archived data",
  EXFILTRATION: "Data sent out",
};

/* ---------- 1. funnel: events → signals → linked → incident ---------- */

const FUNNEL = [
  { n: demo.funnel.events, label: "log events" },
  { n: demo.funnel.signals, label: "detector signals" },
  { n: demo.funnel.linked_signals, label: "linked by cause" },
  { n: demo.funnel.incidents, label: "incident" },
];

export function Funnel({ t }: { t: number }) {
  return (
    <ol className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4" aria-label="Demo case funnel">
      {FUNNEL.map((f, i) => {
        const p = ease(seg(t, 0.03 + i * 0.1, 0.28 + i * 0.1));
        const last = i === FUNNEL.length - 1;
        // bar length on a log scale, so 1 is still visible next to 48,753
        const w = (Math.log10(f.n + 1) / Math.log10(FUNNEL[0].n + 1)) * 100;
        return (
          <li key={f.label} className="min-w-0">
            <div className={`w-cond nums text-[clamp(28px,3.2vw,40px)] leading-none font-[780] ${last ? "text-breach" : "text-graphite"}`}>
              <span aria-hidden="true">{fmt(Math.round(f.n * p))}</span>
              <span className="sr-only">{fmt(f.n)}</span>
            </div>
            <div className="mt-2 h-[3px] rounded-full bg-rule">
              <div className={`h-full rounded-full ${last ? "bg-breach" : "bg-mist"}`} style={{ width: `${Math.max(3, w * p)}%` }} />
            </div>
            <div className="mt-1.5 text-[13px] text-slate">
              {i > 0 && <span aria-hidden="true">› </span>}
              {f.label}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/* ---------- 2. haystack: the real lines around each piece of evidence ---------- */

// each evidence line plus the one real line logged just before it
const HAY = demo.log.filter((l, i, all) => l.step !== null || all[i + 1]?.step != null);

export function Haystack({ t }: { t: number }) {
  const shown = stepsShown(t);
  const rows = useRef<(HTMLDivElement | null)[]>([]);
  const lensRow = rows.current[HAY.findIndex((l) => l.step === Math.max(1, shown))];
  return (
    <figure className="relative m-0 min-w-0">
      <figcaption className="mb-2 text-[13px] text-slate">Raw lines from the case, evidence marked</figcaption>
      <div className="relative overflow-hidden rounded-[3px] border border-rule bg-sheet py-2">
        {HAY.map((l, i) => {
          const hit = l.step !== null && l.step <= shown;
          return (
            <div
              key={i}
              ref={(el) => {
                rows.current[i] = el;
              }}
              title={l.line}
              className={`flex gap-2 py-[2px] pr-3 font-mono text-[11px] leading-[15px] transition-colors duration-200 ${
                hit ? "bg-breach-soft text-graphite shadow-[inset_2px_0_0_var(--color-breach)]" : l.step ? "text-slate" : "text-mist"
              }`}
            >
              <span className={`w-7 shrink-0 text-right nums ${hit ? "font-[600] text-breach" : "text-transparent"}`}>
                {l.step ?? ""}
              </span>
              {/* evidence lines wrap so the part that matters stays visible; the haystack around them stays one line each */}
              <span className={l.step ? "min-w-0 break-all" : "min-w-0 truncate"}>{l.line}</span>
            </div>
          );
        })}
        {/* the lens: a quiet nod to Baker Street, moving to whichever line the replay is reading */}
        {shown > 0 && lensRow && (
          <svg
            aria-hidden="true"
            width="40"
            height="40"
            viewBox="0 0 40 40"
            className="pointer-events-none absolute left-0 transition-[top] duration-150 ease-out"
            style={{ top: lensRow.offsetTop + lensRow.offsetHeight / 2 - 16 }}
          >
            <circle cx="16" cy="16" r="12" fill="none" stroke="var(--color-graphite)" strokeWidth="1.5" opacity=".85" />
            <line x1="25" y1="25" x2="34" y2="34" stroke="var(--color-graphite)" strokeWidth="3" strokeLinecap="round" opacity=".85" />
          </svg>
        )}
      </div>
    </figure>
  );
}

/* ---------- 3. attack path: places × steps, one crimson thread ---------- */

const ip = demo.incident.entry_ip ?? "";
const ROWS = [ip, ...["bastion-01", "app-01", "db-01"].filter((h) => demo.incident.hosts.includes(h))];
const W = 470;
const X0 = 112;
const DX = 33;
const Y0 = 26;
const DY = 52;
const yOf = (host: string) => Y0 + Math.max(0, ROWS.indexOf(host)) * DY;
const PTS = demo.steps.map((s, i) => ({ s, x: X0 + i * DX, y: yOf(s.host) }));
const END = { x: X0 + PTS.length * DX, y: Y0 }; // exfil lands back at the attacker's address
const H = Y0 + (ROWS.length - 1) * DY + 54;

function curve(pts: { x: number; y: number }[]) {
  return pts
    .map((p, i) => {
      if (i === 0) return `M${p.x},${p.y}`;
      const q = pts[i - 1];
      const mx = (q.x + p.x) / 2;
      return `C${mx},${q.y} ${mx},${p.y} ${p.x},${p.y}`;
    })
    .join(" ");
}
const THREAD = curve([...PTS, END]);

export function AttackPathMini({ t }: { t: number }) {
  const shown = stepsShown(t);
  const p = seg(t, STEP_FROM, STEP_FROM + STEP_EVERY * demo.steps.length + 0.06);
  return (
    <figure className="m-0 min-w-0">
      <figcaption className="mb-2 text-[13px] text-slate">Reconstructed path: where each step happened</figcaption>
      <div className="rounded-[3px] border border-rule bg-sheet px-2 py-2">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={`Attack path: ${demo.steps.length} steps across ${ROWS.join(", ")}`}>
          {ROWS.map((r, i) => (
            <g key={r}>
              <line x1={X0 - 16} x2={W - 6} y1={Y0 + i * DY} y2={Y0 + i * DY} stroke="var(--color-rule)" />
              <text
                x={4}
                y={Y0 + i * DY + 4}
                fontSize={i === 0 ? 10.5 : 12}
                fontFamily={i === 0 ? "var(--font-mono)" : "var(--font-sans)"}
                fontWeight={i === 0 ? 400 : 600}
                fill={i === 0 ? "var(--color-breach)" : "var(--color-graphite)"}
              >
                {r}
              </text>
            </g>
          ))}
          <path d={THREAD} fill="none" stroke="var(--color-breach)" strokeWidth="2.25" strokeLinecap="round" pathLength={1} strokeDasharray="1" strokeDashoffset={1 - p} />
          {p > 0.98 && (
            <g>
              <path d={`M${END.x - 7},${END.y - 5} L${END.x + 1},${END.y} L${END.x - 7},${END.y + 5}z`} fill="var(--color-breach)" />
              {demo.incident.gb_out != null && (
                <text x={END.x - 2} y={END.y - 10} fontSize="10.5" textAnchor="end" fill="var(--color-graphite)">
                  {demo.incident.gb_out} GB out
                </text>
              )}
            </g>
          )}
          {PTS.map(({ s, x, y }) => {
            const on = s.order <= shown;
            return (
              <g key={s.order} opacity={on ? 1 : 0.35}>
                <title>{`${s.order}. ${hhmm(s.t)} UTC, ${s.text}`}</title>
                <rect x={x - 12} y={y - 9} width={24} height={18} rx={3} fill={on ? "var(--color-breach)" : "var(--color-sheet)"} stroke={on ? "none" : "var(--color-rule)"} />
                <text x={x} y={y + 4} fontSize="10.5" fontWeight="700" textAnchor="middle" fill={on ? "#fff" : "var(--color-slate)"}>
                  {s.order}
                </text>
                <text x={x} y={H - 22} fontSize="9.5" textAnchor="middle" fill={on ? "var(--color-graphite)" : "var(--color-slate)"}>
                  {STAGE_SHORT[s.stage] ?? s.stage}
                </text>
                <text x={x} y={H - 8} fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle" fill="var(--color-slate)">
                  {hhmm(s.t)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </figure>
  );
}
