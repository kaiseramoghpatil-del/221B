import { useUrlState } from "./lib/url";
import Intake from "./views/Intake";
import CaseView from "./views/CaseView";
import Verify from "./views/Verify";
import SiteHeader from "./views/SiteHeader";

export default function App() {
  const [url, setUrl] = useUrlState();
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      {url.case ? (
        <CaseView url={url} setUrl={setUrl} />
      ) : url.page === "verify" ? (
        <>
          <SiteHeader current="verify" />
          <Verify onOpenCase={(caseId) => setUrl({ case: caseId, page: undefined })} />
        </>
      ) : (
        <Intake onOpen={(caseId) => setUrl({ case: caseId, incident: undefined, view: undefined, claim: undefined })} />
      )}
    </>
  );
}
