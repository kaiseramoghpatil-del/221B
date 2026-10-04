/** Minimal header for the non-case pages. */
export default function SiteHeader({ current }: { current: "home" | "verify" }) {
  const link = (href: string, label: string, active: boolean) => (
    <a
      href={href}
      aria-current={active ? "page" : undefined}
      className={`text-[14px] underline-offset-4 hover:text-graphite hover:underline ${active ? "font-[600] text-graphite" : "text-slate"}`}
    >
      {label}
    </a>
  );
  return (
    <header className="mx-auto flex max-w-[1180px] items-center gap-6 px-6 pt-6 md:px-10">
      {current !== "home" && (
        <a href="/" className="w-cond text-[22px] leading-none font-[750]" aria-label="221B home">
          221B
        </a>
      )}
      <nav aria-label="Site" className="ml-auto flex gap-5">
        {link("/", "Investigate", current === "home")}
        {link("/?page=verify", "How it was tested", current === "verify")}
      </nav>
    </header>
  );
}
