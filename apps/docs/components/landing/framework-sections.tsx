import { Database, KeyRound, Puzzle, Server } from "lucide-react";

const sections = [
  { title: "Servers", body: "FastAPI, Starlette, and Django integrations.", icon: Server },
  { title: "Adapters", body: "SQLAlchemy, Mongo, Redis storage, and memory adapters.", icon: Database },
  { title: "Plugins", body: "Organizations, API keys, SSO, SCIM, passkeys, and more.", icon: Puzzle },
  { title: "Stripe", body: "Checkout, portals, entitlements, and usage tracking.", icon: KeyRound },
];

export function ServerClientTabs() { return <SectionGrid />; }
export function DatabaseSection() { return <SectionGrid />; }
export function IntegrationsSection() { return <SectionGrid />; }
export function PluginEcosystem() { return <SectionGrid />; }
export function SocialProvidersSection() { return <SectionGrid />; }

function SectionGrid() {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {sections.map((item) => <div key={item.title} className="border border-foreground/[0.08] p-3"><item.icon className="mb-2 size-4 text-foreground/45" /><div className="text-sm font-medium">{item.title}</div><p className="mt-1 text-xs text-foreground/50">{item.body}</p></div>)}
    </div>
  );
}
