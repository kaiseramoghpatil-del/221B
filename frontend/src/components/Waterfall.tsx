import type { Gap } from "./types";
import type { Board } from "../lib/board";
import { STAGE, fmtDuration, fmtTime } from "../lib/format";
import { useWidth } from "../lib/useWidth";

const HEAD = 26;
const ROW_H = 36;

type Props = {
  board: Board;
  gaps: Gap[];
  shown: number;
  focusStep: string | null;
  onFocus: (id: string | null) => void;
};

/** Exhibit B: real time on the x-axis. Each place is a span from first to last attacker activity; hops are indented
 *  under the host they came from (trace-waterfall style). Hatched spans mark stretches where logs are missing. */
export default function Waterfall({ board, gaps, shown, focusStep, onFocus }: Props) {
  const [ref, W] = useWidth<HTMLDivElement>();
  const { rows, cells } = board;
  if (!cells.length) return <div ref={ref} />;
  const GUTTER = W < 700 ? 112 : 150;
  const t = (iso: string) => new Date(iso).getTime();
  const t0 = Math.min(...cells.map((c) => t(c.step.t_start)));
  const t1 = Math.max(...cells.map((c) => t(c.step.t_end)));
  const pad = Math.max(60_000, (t1 - t0) * 0.03);
  const a = t0 - pad;
  const b = t1 + pad;
  const x = (ms: number) => GUTTER + ((ms - a) / (b - a)) * (W - GUTTER - 8);
  const H = HEAD + rows.length * ROW_H + 24;
  const cursorMs = shown > 0 && shown < cells.length ? t(cells[shown - 1].step.t_start) : null;
  const nTicks = W < 700 ? 4 : 6;
  const ticks = Array.from({ length: nTicks }, (_, i) => a + ((b - a) * i) / (nTicks - 1));

  return (
    <div ref={ref} className="w-full">
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="block" role="img" aria-label={`Session timeline: the attacker was active for ${fmtDuration(t1 - t0)}`}>
        <defs>
          <pattern id="gap-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--color-watch)" strokeWidth="1.5" />
          </pattern>
        </defs>
        {ticks.map((ms, i) => (
          <g key={i}>
            <line x1={x(ms)} x2={x(ms)} y1={HEAD - 6} y2={H - 20} stroke="var(--color-rule-soft)" />
            <text x={x(ms)} y={H - 5} textAnchor={i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle"} className="nums fill-mist" style={{ fontSize: 12 }}>
              {fmtTime(ms)}
            </text>
          </g>
        ))}
        <text x={W} y={13} textAnchor="end" className="fill-slate" style={{ fontSize: 12.5 }}>
          Attacker active for {fmtDuration(t1 - t0)}, times in UTC
        </text>

        {rows.map((r, i) => {
          const mine = cells.filter((c) => c.row === i);
          if (!mine.length) return null;
          const s = Math.min(...mine.map((c) => t(c.step.t_start)));
          const e = Math.max(...mine.map((c) => t(c.step.t_end)));
          const y = HEAD + i * ROW_H;
          const visible = mine.some((c) => cells.indexOf(c) < shown);
          return (
            <g key={r.id} opacity={visible ? 1 : 0.25} style={{ transition: "opacity 300ms ease" }}>
              <text
                x={r.depth * 12}
                y={y + ROW_H / 2 + 4}
                className={r.kind === "ip" ? "fill-breach" : "fill-graphite"}
                style={{ fontSize: r.kind === "ip" ? 12.5 : 14, fontWeight: 600, fontFamily: r.kind === "ip" ? "var(--font-mono)" : undefined }}
              >
                {r.depth > 0 ? "└ " : ""}
                {r.label}
              </text>
              <rect x={x(s)} y={y + 10} width={Math.max(4, x(e) - x(s))} height={ROW_H - 20} rx={2} fill="var(--color-breach-soft)" stroke="var(--color-breach)" strokeWidth={1} />
              {mine.map((c) => {
                const cxp = x(t(c.step.t_start));
                const active = focusStep === c.step.id;
                return (
                  <g key={c.step.id} onMouseEnter={() => onFocus(c.step.id)} onMouseLeave={() => onFocus(null)}>
                    <title>{`${c.step.order}. ${STAGE[c.step.stage].plain}: ${c.text}, ${fmtTime(c.step.t_start)} UTC`}</title>
                    <rect x={cxp - (active ? 3.5 : 2)} y={y + 5} width={active ? 7 : 4} height={ROW_H - 10} rx={1} fill="var(--color-breach)" />
                  </g>
                );
              })}
            </g>
          );
        })}

        {gaps
          .filter((g) => g.t_start && g.t_end)
          .map((g) => {
            const ri = rows.findIndex((r) => r.label === g.host);
            const y = HEAD + (ri >= 0 ? ri : rows.length - 1) * ROW_H;
            return (
              <g key={g.id}>
                <title>{g.description}</title>
                <rect x={x(t(g.t_start!))} y={y + 4} width={Math.max(4, x(t(g.t_end!)) - x(t(g.t_start!)))} height={ROW_H - 8} fill="url(#gap-hatch)" opacity={0.8} />
              </g>
            );
          })}

        {cursorMs !== null && <line x1={x(cursorMs)} x2={x(cursorMs)} y1={HEAD - 8} y2={H - 20} stroke="var(--color-graphite)" strokeWidth={1.5} />}
      </svg>
    </div>
  );
}
