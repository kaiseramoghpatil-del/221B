import { useEffect, useState } from "react";
import { api, type Schemas } from "./api/client";

// Scaffold only: proves the generated contract types and the API proxy work end to end.
export default function App() {
  const [health, setHealth] = useState<Schemas["Health"] | null>(null);
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);
  return (
    <main className="min-h-full grid place-items-center">
      <div className="text-center">
        <h1 className="serif text-6xl tracking-tight">221B</h1>
        <p className="mono mt-3 text-sm" style={{ color: "var(--paper-dim)" }}>
          forensic incident reconstruction
        </p>
        <p className="mono mt-8 text-xs" style={{ color: health ? "var(--ok)" : "var(--signal)" }}>
          {health ? `api ok · contract ${health.contract_version} · pipeline ${health.pipeline_version}` : "api offline"}
        </p>
      </div>
    </main>
  );
}
