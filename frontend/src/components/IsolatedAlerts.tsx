import type { Incident, NaiveAlert } from "../api/client";
import { entityKind, entityLabel, fmtDateTime } from "../lib/format";

/** What a per-rule console would show: every detector hit as its own alert, in time order. */
export default function IsolatedAlerts({ alerts, incidents, onPick }: { alerts: NaiveAlert[]; incidents: Incident[]; onPick: (incidentId: string) => void }) {
  const where = new Map<string, Incident>();
  incidents.forEach((i) => i.signal_ids.forEach((s) => where.set(s, i)));
  const ordered = [...alerts].sort((a, b) => a.t.localeCompare(b.t));
  const shown = ordered.slice(0, 200);
  const inInc = alerts.filter((a) => where.get(a.signal_id)?.status === "incident").length;
  return (
    <section aria-labelledby="iso-h">
      <h1 id="iso-h" className="w-cond text-[38px] leading-[1.06] font-[700]">
        {alerts.length} alerts, one per rule hit, in time order.
      </h1>
      <p className="pretty mt-2 max-w-[68ch] text-slate">
        This is the same detector output, shown the way a per-rule console shows it: every hit on its own line. {inInc} of these are
        the intrusion. Nothing in a list like this says which ones, or that they are one story. The right-hand column is what 221B
        worked out.
      </p>
      <div className="mt-5 overflow-x-auto rounded-[4px] border border-rule bg-sheet">
        <table className="w-full min-w-[640px] text-left text-[13.5px]">
          <thead className="border-b border-rule text-[12.5px] text-slate">
            <tr>
              <th scope="col" className="px-3 py-2 font-[500]">Severity</th>
              <th scope="col" className="px-3 py-2 font-[500]">Alert</th>
              <th scope="col" className="px-3 py-2 font-[500]">Subject</th>
              <th scope="col" className="px-3 py-2 font-[500]">Time</th>
              <th scope="col" className="px-3 py-2 font-[500]">What 221B concluded</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a) => {
              const inc = where.get(a.signal_id);
              const verdict =
                inc?.status === "incident"
                  ? { t: "Part of the intrusion", c: "text-breach font-[600]" }
                  : inc?.status === "watchlist"
                    ? { t: "Watchlist", c: "text-watch" }
                    : { t: "Isolated", c: "text-slate" };
              return (
                <tr key={a.signal_id} className="border-b border-rule-soft last:border-0">
                  <td className="px-3 py-2">
                    <span className="block h-1.5 w-16 rounded-sm bg-rule-soft">
                      <span className="block h-1.5 rounded-sm bg-graphite" style={{ width: `${a.severity * 100}%` }} />
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-[11.5px] text-slate">{a.detector}</span> {a.title}
                  </td>
                  <td className={`px-3 py-2 ${entityKind(a.entity) === "ip" ? "font-mono text-[12.5px]" : ""}`} translate="no">
                    {entityLabel(a.entity)}
                  </td>
                  <td className="nums px-3 py-2 whitespace-nowrap text-slate">{fmtDateTime(a.t)}</td>
                  <td className="px-3 py-2">
                    {inc ? (
                      <button type="button" onClick={() => onPick(inc.id)} className={`underline-offset-2 hover:underline ${verdict.c}`}>
                        {verdict.t}
                      </button>
                    ) : (
                      <span className={verdict.c}>{verdict.t}</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {alerts.length > shown.length && <p className="mt-2 text-[13px] text-slate">Showing the first 200 of {alerts.length}.</p>}
    </section>
  );
}
