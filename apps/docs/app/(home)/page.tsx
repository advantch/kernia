import { ArrowRight, Check, Terminal } from "lucide-react";
import Link from "next/link";
import { KerniaMark, homeCards } from "@/lib/shared";

const install = `pip install kernia kernia-fastapi kernia-sqlalchemy
kernia init --adapter sqlite --framework fastapi
kernia generate && kernia migrate`;

const python = `from kernia import KerniaOptions
from kernia.auth import init
from kernia.plugins.email_password import email_and_password
from kernia_fastapi import mount_auth

auth = init(KerniaOptions(
    database=adapter,
    secret="change-me",
    plugins=[email_and_password()],
))

mount_auth(app, auth, prefix="/api/auth")`;

export default function HomePage() {
  return (
    <main className="relative overflow-hidden">
      <div className="kernia-grid pointer-events-none absolute inset-x-0 top-0 h-[620px] text-foreground/40" />
      <section className="kernia-hero mx-auto grid min-h-[640px] w-full max-w-7xl items-center gap-10 px-6 py-20 lg:grid-cols-[minmax(0,1fr)_520px]">
        <div className="relative z-10">
          <div className="mb-7 inline-flex items-center gap-2 rounded-full border bg-background/80 px-3 py-1 text-sm text-muted-foreground shadow-sm backdrop-blur">
            <KerniaMark className="size-5" />
            Python implementation compatible with Better Auth
          </div>
          <h1 className="max-w-4xl text-5xl font-semibold tracking-normal sm:text-6xl lg:text-7xl">
            Authentication docs for Python teams shipping SaaS.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-muted-foreground">
            Kernia brings the Better Auth wire protocol to FastAPI, Starlette,
            and Django, with Python package names, adapters, plugins, admin
            config, Stripe billing, and a full reference SaaS demo.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              href="/docs"
              className="inline-flex h-11 items-center gap-2 rounded-full bg-primary px-5 text-sm font-medium text-primary-foreground"
            >
              Start reading
              <ArrowRight className="size-4" />
            </Link>
            <Link
              href="/docs/examples/fastapi-saas-demo"
              className="inline-flex h-11 items-center gap-2 rounded-full border bg-background px-5 text-sm font-medium"
            >
              Open the SaaS demo
            </Link>
          </div>
          <div className="mt-8 grid max-w-2xl gap-2 text-sm text-muted-foreground sm:grid-cols-3">
            {["Better Auth JS client", "Python package family", "No vendored upstream source"].map((item) => (
              <div key={item} className="flex items-center gap-2">
                <Check className="size-4 text-emerald-500" />
                {item}
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 rounded-2xl border bg-card/90 p-3 shadow-2xl shadow-emerald-950/10 backdrop-blur">
          <div className="rounded-xl border bg-background">
            <div className="flex items-center gap-2 border-b px-4 py-3 text-sm text-muted-foreground">
              <Terminal className="size-4" />
              kernia quickstart
            </div>
            <pre className="overflow-auto p-5 text-sm leading-7"><code>{install}</code></pre>
            <div className="border-t" />
            <pre className="overflow-auto p-5 text-sm leading-7"><code>{python}</code></pre>
          </div>
        </div>
      </section>

      <section className="mx-auto grid w-full max-w-7xl gap-4 px-6 pb-20 md:grid-cols-3">
        {homeCards.map((card) => (
          <div key={card.title} className="rounded-xl border bg-card p-6">
            <div className="mb-4 grid size-10 place-items-center rounded-lg bg-emerald-500/10 text-emerald-600">
              {card.icon}
            </div>
            <h2 className="text-lg font-semibold">{card.title}</h2>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{card.body}</p>
          </div>
        ))}
      </section>
    </main>
  );
}
