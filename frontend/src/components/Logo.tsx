/** 221B wordmark: the door number in an italic serif, set in an oval plaque. */
export default function Logo({ height = 32, className = "" }: { height?: number; className?: string }) {
  return (
    <svg viewBox="0 0 120 44" height={height} role="img" aria-label="221B" className={className}>
      <rect x="1" y="1" width="118" height="42" rx="21" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="5" y="5" width="110" height="34" rx="17" fill="none" stroke="currentColor" strokeWidth="0.75" opacity="0.45" />
      <text
        x="60"
        y="31"
        textAnchor="middle"
        fontFamily="Georgia, 'Times New Roman', serif"
        fontStyle="italic"
        fontWeight="700"
        fontSize="26"
        letterSpacing="1.5"
        fill="currentColor"
      >
        221<tspan fill="var(--color-breach)">B</tspan>
      </text>
    </svg>
  );
}
