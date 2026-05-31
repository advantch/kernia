const logos = [
  "FastAPI",
  "Starlette",
  "Django",
  "SQLAlchemy",
  "Redis",
  "Mongo",
  "Stripe",
  "SSO",
  "SCIM",
  "Passkeys",
  "API keys",
  "Vite",
];

function LogoItem({ name }: { name: string }) {
  return (
    <div className="flex shrink-0 items-center gap-2 px-5 text-foreground/60 dark:text-foreground/40">
      <span className="flex size-4 items-center justify-center border border-foreground/[0.08] font-mono text-[8px]">
        {name.slice(0, 1)}
      </span>
      <span className="whitespace-nowrap text-xs font-medium tracking-wide">
        {name}
      </span>
    </div>
  );
}

export function TrustedBy() {
  return (
    <div className="space-y-3">
      <div className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0 z-10"
          style={{
            maskImage:
              "linear-gradient(to right, transparent, black 15%, black 85%, transparent)",
            WebkitMaskImage:
              "linear-gradient(to right, transparent, black 15%, black 85%, transparent)",
          }}
        >
          <div className="flex w-fit animate-logo-marquee">
            {[0, 1].map((setIndex) => (
              <div key={setIndex} className="flex shrink-0">
                {logos.map((logo) => (
                  <LogoItem key={`${setIndex}-${logo}`} name={logo} />
                ))}
              </div>
            ))}
          </div>
        </div>
        <div className="invisible flex" aria-hidden="true">
          <LogoItem name={logos[0]} />
        </div>
      </div>
    </div>
  );
}
