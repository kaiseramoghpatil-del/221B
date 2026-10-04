import { useEffect, useRef, useState } from "react";
import { api, ApiError, type RevealResponse } from "../api/client";
import { fmtPct } from "../lib/format";

const KIND: Record<string, string> = {
  entry_ip: "Address the intruder logged in from",
  attacker_infrastructure: "All attacker addresses (incl. rotation)",
  compromised_account: "Compromised account",
  data_stolen_from: "Host the data was taken from",
};

export default function RevealDialog({ caseId, open, onClose }: { caseId: string; open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [data, setData] = useState<RevealResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      d.showModal();
      if (!data) api.reveal(caseId).then(setData, (e) => setErr(e instanceof ApiError ? e.message : "Reveal failed."));
    }
    if (!open && d.open) d.close();
  }, [open, caseId, data]);

  const card = data?.scorecard;
  const base = (card?.baselines ?? {}) as Record<string, Record<string, number>>;
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby="reveal-h"
      className="m-auto w-[min(860px,94vw)] rounded-[6px] border border-rule bg-paper p-0 text-graphite backdrop:bg-graphite/40"
    >
      <div className="scroll-quiet max-h-[86vh] overflow-y-auto p-7">
        <div className="flex items-start gap-4">
          <div>
            <p className="text-[13px] text-slate">Hidden until now</p>
            <h2 id="reveal-h" className="w-cond text-[34px] leading-tight font-[700]">
              The answer key
            </h2>
          </div>
          <button type="button" onClick={onClose} className="ml-auto rounded-[4px] px-2 py-1 text-[13px] text-slate hover:bg-rule-soft">
            Close
          </button>
        </div>
        <p aria-live="polite" className="mt-1 text-[14px] text-slate">
          {err ?? (!data ? "Comparing the verdict with the generator’s ground truth…" : `Scenario ${data.truth.scenario_id}, entry by ${data.truth.entry_vector?.replace("_", " ") ?? "nobody (clean case)"}.`)}
        </p>

        {data && (
          <>
            <table className="mt-5 w-full text-left text-[14px]">
              <thead className="border-b border-rule text-[12.5px] text-slate">
                <tr>
                  <th scope="col" className="py-2 font-[500]">Question</th>
                  <th scope="col" className="py-2 font-[500]">Truth</th>
                  <th scope="col" className="py-2 font-[500]">221B said</th>
                  <th scope="col" className="py-2 font-[500]">Result</th>
                </tr>
              </thead>
              <tbody>
                {data.matches.map((m) => {
                  const ok = m.truth.length > 0 && m.misses.length === 0 && m.false_positives.length === 0;
                  const partial = m.hits.length > 0 && !ok;
                  return (
                    <tr key={m.kind} className="border-b border-rule-soft align-top">
                      <td className="py-2 pr-3">{KIND[m.kind] ?? m.kind}</td>
                      <td className="py-2 pr-3 font-mono text-[12.5px]">{m.truth.slice(0, 4).join(", ") || "none"}{m.truth.length > 4 ? ` +${m.truth.length - 4}` : ""}</td>
                      <td className="py-2 pr-3 font-mono text-[12.5px]">{m.predicted.slice(0, 4).join(", ") || "none"}</td>
                      <td className={`py-2 font-[650] ${ok ? "text-cleared" : partial ? "text-watch" : "text-breach"}`}>
                        {ok ? "Match" : partial ? `${m.hits.length} of ${m.truth.length}` : m.truth.length ? "Missed" : "n/a"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            <dl className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
              {[
                ["Steps in the right order", card?.stage_order_accuracy != null ? fmtPct(card.stage_order_accuracy) : "n/a"],
                ["Incident signals that were real attack", card?.cluster_purity != null ? fmtPct(card.cluster_purity) : "n/a"],
                ["Innocent entities accused", String(card?.false_suspect_count ?? 0)],
                ["Missing-log stretches flagged", card?.gap_recall != null ? fmtPct(card.gap_recall) : "none injected"],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt className="text-[12.5px] text-slate">{k}</dt>
                  <dd className="w-cond nums text-[26px] font-[700]">{v}</dd>
                </div>
              ))}
            </dl>

            <h3 className="w-semi mt-7 text-[16px] font-[650]">Same detector output, three ways of reading it</h3>
            <table className="mt-2 w-full text-left text-[14px]">
              <tbody>
                <tr className="border-b border-rule-soft">
                  <th scope="row" className="py-2 pr-3 font-[500]">Every hit is an alert</th>
                  <td className="nums py-2">
                    {base.B0_naive_alerts?.alerts} alerts, {fmtPct(base.B0_naive_alerts?.precision ?? 0)} of them about the attack
                  </td>
                </tr>
                <tr className="border-b border-rule-soft">
                  <th scope="row" className="py-2 pr-3 font-[500]">Group hits that are close in time</th>
                  <td className="nums py-2">
                    {base.B1_time_window?.groups} groups; the best one covers {fmtPct(base.B1_time_window?.best_group_stage_recall ?? 0)} of the attack’s stages
                  </td>
                </tr>
                <tr>
                  <th scope="row" className="py-2 pr-3 font-[650] text-breach">221B: link hits by what each step needed</th>
                  <td className="nums py-2 font-[650]">
                    {base.B2_221B?.incidents} incident covering {fmtPct(base.B2_221B?.stage_recall ?? 0)} of the stages, {fmtPct(base.B2_221B?.purity ?? 0)} pure
                  </td>
                </tr>
              </tbody>
            </table>
          </>
        )}
      </div>
    </dialog>
  );
}
