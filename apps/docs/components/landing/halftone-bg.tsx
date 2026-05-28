export function HalftoneBg({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`bg-dot text-foreground/[0.06] ${className}`} />;
}
