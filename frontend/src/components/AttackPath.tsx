import type { Board, Cell } from "../lib/board";
import { ROLE, STAGE, fmtTime } from "../lib/format";
import { useWidth } from "../lib/useWidth";

const HEAD = 46;
const ROW_H = 66;
const CHIP_H = 42;

type Props = {
  board: Board;
  shown: number; // number of steps revealed (replay position)
  focusStep: string | null;
  onFocus: (stepId: string | null) => void;
  onOpen: (cell: Cell) => void;
};

/** Exhibit A: places (rows) x stages (columns), one crimson thread through the attacker's steps in time order.
 *  Rendered at true pixel size so text stays legible on a projector. */
export default function AttackPath({ board, shown, focusStep, onFocus, onOpen }: Props) {
  const [ref, W] = useWidth<HTMLDivElement>();
  const { rows, cols, cells } = board;
  const GUTTER = W < 700 ? 112 : 150;
  const colW = (W - GUTTER - 8) / Math.max(1, cols.length);
  const H = HEAD + rows.length * ROW_H + 8;
  const chipW = Math.max(62, Math.min(colW - 5, 140));
  const cx = (c: number) => GUTTER + colW * c + colW / 2;
  const cy = (r: number) => HEAD + ROW_H * r + ROW_H / 2;
  const maxChars = Math.floor((chipW - 10) / 5.5);

  const seen = new Map<string, number>();
  const pos = cells.map((cell) => {
    const k = `${cell.row}:${cell.col}`;
    const n = seen.get(k) ?? 0;
    seen.set(k, n + 1);
    return { x: cx(cell.col) + n * 6, y: cy(cell.row) + n * 5 };
  });
  const seg = (a: { x: number; y: number }, b: { x: number; y: number }) => {
    const mx = (a.x + b.x) / 2;
    return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`;
  };
  const last = cells.length - 1;
  const terminal = last >= 0 && cells[last].terminalRow !== undefined ? cells[last].terminalRow! : null;
  const termEnd = terminal !== null ? { x: Math.min(W - 10, pos[last].x + chipW / 2 + 18), y: cy(terminal) } : null;

  return (
    <div ref={ref} className="w-full">
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="block" role="img" aria-labelledby="ap-title ap-desc">
        <title id="ap-title">Attack path</title>
        <desc id="ap-desc">{cells.map((c) => `${c.step.order}. ${STAGE[c.step.stage].plain} on ${rows[c.row].label}: ${c.text}`).join(". ")}</desc>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-breach)" />
          </marker>
        </defs>

        {cols.map((s, c) => (
          <g key={s}>
            {c % 2 === 1 && <rect x={GUTTER + colW * c} y={HEAD - 4} width={colW} height={rows.length * ROW_H + 8} fill="var(--color-rule-soft)" opacity={0.55} />}
            <text x={cx(c)} y={18} textAnchor="middle" className="fill-graphite" style={{ fontSize: 13.5, fontWeight: 650, fontStretch: "82%" }}>
              {STAGE[s].short}
            </text>
            <text x={cx(c)} y={34} textAnchor="middle" className="fill-mist" style={{ fontSize: 10.5, fontStretch: "80%" }}>
              {STAGE[s].tactic.split(" / ")[0]}
            </text>
          </g>
        ))}

        {rows.map((r, i) => (
          <g key={r.id}>
            <line x1={GUTTER - 6} x2={W} y1={cy(i)} y2={cy(i)} stroke="var(--color-rule)" strokeWidth={1} />
            <text
              x={r.depth * 12}
              y={cy(i) - 3}
              className={r.kind === "ip" ? "fill-breach" : "fill-graphite"}
              style={{ fontSize: r.kind === "ip" ? 12.5 : 14.5, fontWeight: 650, fontFamily: r.kind === "ip" ? "var(--font-mono)" : undefined }}
            >
              {r.depth > 0 ? "└ " : ""}
              {r.label}
            </text>
            <text x={r.depth * 12} y={cy(i) + 14} className="fill-slate" style={{ fontSize: 11.5 }}>
              {r.kind === "ip" ? "attacker, on the internet" : ROLE[r.role]?.replace("Used as a ", "") ?? "host"}
            </text>
          </g>
        ))}

        {cells.slice(1).map((cell, j) => (
          <path
            key={cell.step.id}
            d={seg(pos[j], pos[j + 1])}
            fill="none"
            stroke="var(--color-breach)"
            strokeWidth={2.5}
            strokeDasharray={cell.step.inferred ? "6 5" : undefined}
            opacity={j + 1 < shown ? 1 : 0}
            style={{ transition: "opacity 320ms ease" }}
          />
        ))}
        {termEnd && (
          <path
            d={seg({ x: pos[last].x + chipW / 2, y: pos[last].y }, termEnd)}
            fill="none"
            stroke="var(--color-breach)"
            strokeWidth={2.5}
            markerEnd="url(#arrow)"
            opacity={shown > last ? 1 : 0}
            style={{ transition: "opacity 320ms ease" }}
          />
        )}

        {cells.map((cell, i) => {
          const p = pos[i];
          const isVisible = i < shown;
          const active = focusStep === cell.step.id;
          const text = cell.text.length > maxChars ? cell.text.slice(0, maxChars - 1) + "…" : cell.text;
          return (
            <g
              key={cell.step.id}
              transform={`translate(${p.x - chipW / 2}, ${p.y - CHIP_H / 2})`}
              opacity={isVisible ? 1 : 0.1}
              style={{ transition: "opacity 320ms ease", cursor: "pointer" }}
              role="button"
              tabIndex={isVisible ? 0 : -1}
              aria-label={`Step ${cell.step.order}: ${STAGE[cell.step.stage].plain}, ${cell.text}, ${fmtTime(cell.step.t_start)} UTC. Open the evidence.`}
              onMouseEnter={() => onFocus(cell.step.id)}
              onMouseLeave={() => onFocus(null)}
              onFocus={() => onFocus(cell.step.id)}
              onBlur={() => onFocus(null)}
              onClick={() => onOpen(cell)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onOpen(cell);
                }
              }}
            >
              <title>{`${cell.step.order}. ${STAGE[cell.step.stage].plain}: ${cell.text}`}</title>
              <rect
                width={chipW}
                height={CHIP_H}
                rx={4}
                fill={active ? "var(--color-breach)" : "var(--color-sheet)"}
                stroke="var(--color-breach)"
                strokeWidth={1.5}
                strokeDasharray={cell.step.inferred ? "4 3" : undefined}
              />
              <text x={7} y={15} style={{ fontSize: 11, fontWeight: 650 }} className={`nums ${active ? "fill-white" : "fill-breach"}`}>
                {`${cell.step.order} ${fmtTime(cell.step.t_start)}`}
              </text>
              <text x={7} y={32} style={{ fontSize: 12.5, fontWeight: 580, fontStretch: "75%" }} className={active ? "fill-white" : "fill-graphite"}>
                {text}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
