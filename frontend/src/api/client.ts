import type { components } from "./types";

export type Schemas = components["schemas"];

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetch("/api/health").then((r) => j<Schemas["Health"]>(r)),
  createScenario: (seed: number, params: Partial<Schemas["ScenarioParams"]> = {}) =>
    fetch("/api/scenarios", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ seed, params }),
    }).then((r) => j<Schemas["CaseCreated"]>(r)),
  summary: (caseId: string) => fetch(`/api/cases/${caseId}/summary`).then((r) => j<Schemas["CaseSummary"]>(r)),
};
