import type { components } from "./types";

export type S = components["schemas"];
export type CaseSummary = S["CaseSummary"];
export type Incident = S["Incident"];
export type IncidentDetail = S["IncidentDetail"];
export type AttackGraph = S["AttackGraph"];
export type AttackStep = S["AttackStep"];
export type Claim = S["Claim"];
export type Suspect = S["Suspect"];
export type Dismissal = S["Dismissal"];
export type NaiveAlert = S["NaiveAlert"];
export type EventContext = S["EventContext"];
export type RevealResponse = S["RevealResponse"];
export type ScenarioParams = S["ScenarioParams"];
export type Signal = S["Signal"];
export type Stage = S["Stage"];

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

const get = <T>(path: string) => fetch(path).then((r) => j<T>(r));

export const api = {
  health: () => get<S["Health"]>("/api/health"),
  createScenario: (seed: number, params: Partial<ScenarioParams> = {}) =>
    fetch("/api/scenarios", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ seed, params }),
    }).then((r) => j<S["CaseCreated"]>(r)),
  upload: (files: File[]) => {
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f, f.name));
    return fetch("/api/cases", { method: "POST", body: fd }).then((r) => j<S["CaseCreated"]>(r));
  },
  summary: (id: string) => get<CaseSummary>(`/api/cases/${id}/summary`),
  incidents: (id: string) => get<S["IncidentList"]>(`/api/cases/${id}/incidents`),
  incident: (id: string, iid: string) => get<IncidentDetail>(`/api/cases/${id}/incidents/${iid}`),
  replay: (id: string, iid: string) => get<AttackGraph>(`/api/cases/${id}/incidents/${iid}/replay`),
  suspects: (id: string) => get<S["SuspectList"]>(`/api/cases/${id}/suspects`),
  dismissals: (id: string) => get<S["DismissalList"]>(`/api/cases/${id}/dismissals`),
  naive: (id: string) => get<S["NaiveView"]>(`/api/cases/${id}/naive`),
  event: (id: string, eid: string, context = 4) => get<EventContext>(`/api/cases/${id}/events/${eid}?context=${context}`),
  evalLatest: () => get<S["EvalReport"]>("/api/eval/latest"),
  evalHeldout: () => get<S["EvalReport"]>("/api/eval/heldout"),
  reveal: (id: string) => fetch(`/api/cases/${id}/reveal`, { method: "POST" }).then((r) => j<RevealResponse>(r)),
};
