import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  Building2,
  CheckCircle2,
  CreditCard,
  KeyRound,
  Link2,
  Lock,
  LogOut,
  Mail,
  Plus,
  RefreshCw,
  Radio,
  Settings,
  ShieldCheck,
  Sparkles,
  UserRound,
  Users,
  Webhook,
} from "lucide-react";

import { authClient } from "./auth-client";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

type SessionData = Awaited<ReturnType<typeof authClient.getSession>>["data"];
type Section = "overview" | "settings" | "admin" | "events";

type EventRow = {
  event: string;
  organization_id: string;
  user_id: string;
  role: string;
};

type AuthMethod = { enabled?: boolean; label?: string };
type Organization = { id: string; name: string; slug: string; role?: string };
type ApiKeyRow = { id: string; name?: string; keyPrefix?: string; lastUsedAt?: number };
type SessionRow = { id: string; current?: boolean; expiresAt?: number; userAgent?: string };
type AccountRow = { id: string; providerId: string; accountId: string; createdAt?: number };

const defaultEmail = "founder@acme.test";
const defaultPassword = "correcthorse";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/auth${path}`, {
    credentials: "include",
    headers: { "content-type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || data.code || `HTTP ${res.status}`);
  return data as T;
}

function initials(value: string) {
  return value
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

function slugify(value: string) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

export function App() {
  const [section, setSection] = useState<Section>("overview");
  const [session, setSession] = useState<SessionData>(null);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState(defaultEmail);
  const [password, setPassword] = useState(defaultPassword);
  const [name, setName] = useState("Avery Stone");
  const [orgName, setOrgName] = useState("Acme Workspace");
  const [apiKeyName, setApiKeyName] = useState("Production key");
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [methods, setMethods] = useState<Record<string, AuthMethod>>({});
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKeyRow[]>([]);
  const [products, setProducts] = useState<any[]>([]);
  const [prices, setPrices] = useState<any[]>([]);
  const [emailClients, setEmailClients] = useState<any[]>([]);
  const [stripeConfig, setStripeConfig] = useState<any>({});
  const [billingCheck, setBillingCheck] = useState<any>(null);

  const displayName = session?.user.name || session?.user.email || "Operator";
  const enabledMethods = useMemo(
    () => Object.entries(methods).filter(([, method]) => method.enabled),
    [methods],
  );
  const disabledMethods = useMemo(
    () => Object.entries(methods).filter(([, method]) => !method.enabled),
    [methods],
  );

  async function loadPublicConfig() {
    const data = await api<{ methods: Record<string, AuthMethod> }>("/admin/config/public-auth");
    setMethods(data.methods || {});
  }

  async function refresh() {
    await loadPublicConfig();
    const { data } = await authClient.getSession();
    setSession(data);
    setLoading(false);
    if (data) await refreshSignedIn();
  }

  async function refreshSignedIn() {
    await Promise.allSettled([
      refreshOrgs(),
      refreshSettings(),
      refreshAdmin(),
      refreshBilling(),
    ]);
  }

  async function refreshOrgs() {
    const { data } = await authClient.organization.list();
    setOrgs(Array.isArray(data) ? (data as Organization[]) : []);
  }

  async function refreshSettings() {
    const [sessionData, accountData, keyData] = await Promise.all([
      api<SessionRow[]>("/list-sessions"),
      api<AccountRow[]>("/list-accounts"),
      api<{ keys: ApiKeyRow[] }>("/api-key/list"),
    ]);
    setSessions(sessionData);
    setAccounts(accountData);
    setApiKeys(keyData.keys || []);
  }

  async function refreshAdmin() {
    const [authData, emailData, stripeData] = await Promise.all([
      api<{ methods: Record<string, AuthMethod> }>("/admin/config/auth-methods"),
      api<{ clients: any[] }>("/admin/config/email-clients"),
      api<{ stripe: any }>("/admin/config/stripe"),
    ]);
    setMethods(authData.methods || {});
    setEmailClients(emailData.clients || []);
    setStripeConfig(stripeData.stripe || {});
  }

  async function refreshBilling() {
    const [productData, priceData, checkData] = await Promise.allSettled([
      api<{ products: any[] }>("/stripe/products"),
      api<{ prices: any[] }>("/stripe/prices"),
      api<any>("/billing/check", {
        method: "POST",
        body: JSON.stringify({ feature: "projects", required: 1 }),
      }),
    ]);
    if (productData.status === "fulfilled") setProducts(productData.value.products || []);
    if (priceData.status === "fulfilled") setPrices(priceData.value.prices || []);
    if (checkData.status === "fulfilled") setBillingCheck(checkData.value);
  }

  useEffect(() => {
    refresh();
  }, []);

  async function run(action: () => Promise<void>) {
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function signUp(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      const { error: err } = await authClient.signUp.email({
        email,
        password,
        name: name || email.split("@")[0],
      });
      if (err) throw new Error(err.message || String(err.code));
      await refresh();
    });
  }

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      const { error: err } = await authClient.signIn.email({ email, password });
      if (err) throw new Error(err.message || String(err.code));
      await refresh();
    });
  }

  async function signOut() {
    await authClient.signOut();
    setSession(null);
    setOrgs([]);
    setSection("overview");
  }

  async function createOrg(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      const { error: err } = await authClient.organization.create({
        name: orgName,
        slug: slugify(orgName),
      });
      if (err) throw new Error(err.message || String(err.code));
      setOrgName("");
      await refreshOrgs();
    });
  }

  async function createApiKey(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      const data = await api<{ key: string }>("/api-key/create", {
        method: "POST",
        body: JSON.stringify({ name: apiKeyName }),
      });
      setNewApiKey(data.key);
      await refreshSettings();
    });
  }

  async function toggleMethod(id: string, enabled: boolean) {
    await run(async () => {
      const next = { ...methods, [id]: { ...methods[id], enabled } };
      const data = await api<{ methods: Record<string, AuthMethod> }>("/admin/config/auth-methods", {
        method: "POST",
        body: JSON.stringify({ value: next }),
      });
      setMethods(data.methods || {});
    });
  }

  async function saveDemoEmailClient() {
    await run(async () => {
      const data = await api<{ clients: any[] }>("/admin/config/email-clients", {
        method: "POST",
        body: JSON.stringify({
          value: {
            clients: [
              {
                id: "postmark-main",
                kind: "postmark",
                from: "support@example.com",
                apiKey: "pm_demo_secret",
              },
            ],
          },
          secretFields: ["apiKey"],
        }),
      });
      setEmailClients(data.clients || []);
    });
  }

  async function saveDemoStripeConfig() {
    await run(async () => {
      const data = await api<{ stripe: any }>("/admin/config/stripe", {
        method: "POST",
        body: JSON.stringify({
          value: { mode: "test", apiKey: "sk_test_demo", webhookSecret: "whsec_demo" },
        }),
      });
      setStripeConfig(data.stripe || {});
    });
  }

  async function syncStripe() {
    await run(async () => {
      await api("/stripe/catalog/sync", { method: "POST" });
      await refreshBilling();
    });
  }

  if (loading) {
    return (
      <main className="grid min-h-screen place-items-center bg-background px-4">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle>Opening workspace</CardTitle>
            <CardDescription>Checking the Kernia session.</CardDescription>
          </CardHeader>
        </Card>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col px-4 py-4 sm:px-6 lg:px-8">
        <Header signedIn={!!session} />
        {error && (
          <div className="mt-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700" data-testid="error">
            {error}
          </div>
        )}

        {session ? (
          <section className="grid flex-1 gap-4 py-4 lg:grid-cols-[260px_minmax(0,1fr)]">
            <Sidebar
              displayName={displayName}
              email={session.user.email}
              section={section}
              setSection={setSection}
              signOut={signOut}
            />
            <div className="grid content-start gap-4">
              {section === "overview" && (
                <Overview
                  orgs={orgs}
                  sessions={sessions}
                  apiKeys={apiKeys}
                  billingCheck={billingCheck}
                  orgName={orgName}
                  setOrgName={setOrgName}
                  createOrg={createOrg}
                />
              )}
              {section === "settings" && (
                <SettingsPanel
                  session={session}
                  accounts={accounts}
                  sessions={sessions}
                  apiKeys={apiKeys}
                  apiKeyName={apiKeyName}
                  setApiKeyName={setApiKeyName}
                  createApiKey={createApiKey}
                  newApiKey={newApiKey}
                  refreshSettings={refreshSettings}
                />
              )}
              {section === "admin" && (
                <AdminPanel
                  methods={methods}
                  enabledMethods={enabledMethods}
                  disabledMethods={disabledMethods}
                  toggleMethod={toggleMethod}
                  emailClients={emailClients}
                  saveDemoEmailClient={saveDemoEmailClient}
                  stripeConfig={stripeConfig}
                  saveDemoStripeConfig={saveDemoStripeConfig}
                  products={products}
                  prices={prices}
                  syncStripe={syncStripe}
                />
              )}
              {section === "events" && <EventsPanel />}
            </div>
          </section>
        ) : (
          <LoginScreen
            methods={methods}
            enabledMethods={enabledMethods}
            disabledMethods={disabledMethods}
            email={email}
            setEmail={setEmail}
            password={password}
            setPassword={setPassword}
            name={name}
            setName={setName}
            signUp={signUp}
            signIn={signIn}
          />
        )}
      </div>
    </main>
  );
}

function Header({ signedIn }: { signedIn: boolean }) {
  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border">
      <div className="flex items-center gap-3">
        <div className="grid size-8 place-items-center rounded-lg bg-primary text-white">
          <ShieldCheck className="size-4" />
        </div>
        <div>
          <div className="text-sm font-semibold leading-none">Kernia</div>
          <div className="mt-1 text-xs text-muted-foreground">SaaS control plane</div>
        </div>
      </div>
      <Badge variant="outline" className="gap-1 border-border bg-muted">
        <CheckCircle2 className="size-3" />
        {signedIn ? "Session live" : "FastAPI live"}
      </Badge>
    </header>
  );
}

function LoginScreen(props: {
  methods: Record<string, AuthMethod>;
  enabledMethods: [string, AuthMethod][];
  disabledMethods: [string, AuthMethod][];
  email: string;
  setEmail: (value: string) => void;
  password: string;
  setPassword: (value: string) => void;
  name: string;
  setName: (value: string) => void;
  signUp: (e: React.FormEvent) => Promise<void>;
  signIn: (e: React.FormEvent) => Promise<void>;
}) {
  return (
    <section className="grid flex-1 items-center gap-6 py-8 lg:grid-cols-[minmax(0,1fr)_440px]">
      <div className="max-w-2xl">
        <Badge className="mb-4 gap-1 bg-secondary text-secondary-foreground" variant="secondary">
          <Sparkles className="size-3" />
          Kernia + Better Auth JS client
        </Badge>
        <h1 className="max-w-xl text-4xl font-semibold tracking-normal text-foreground sm:text-5xl">
          SaaS auth, billing, and admin on FastAPI.
        </h1>
        <p className="mt-4 max-w-xl text-base leading-7 text-muted-foreground">
          The demo signs up users, persists sessions, manages organizations, exposes settings, configures admin auth, and imports Stripe catalog data.
        </p>
        <div className="mt-6 grid gap-3 sm:grid-cols-3">
          {[
            ["Auth", `${props.enabledMethods.length} enabled methods`],
            ["Settings", "profile, accounts, sessions, keys"],
            ["Billing", "catalog, entitlements, usage"],
          ].map(([title, body]) => (
            <div key={title} className="rounded-lg border border-border bg-card p-4">
              <div className="text-sm font-medium">{title}</div>
              <div className="mt-1 text-xs leading-5 text-muted-foreground">{body}</div>
            </div>
          ))}
        </div>
        <div className="mt-6 flex flex-wrap gap-2">
          {Object.entries(props.methods).map(([id, method]) => (
            <Badge key={id} variant={method.enabled ? "default" : "outline"}>
              {method.label || id}
            </Badge>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Enter workspace</CardTitle>
          <CardDescription>Use the defaults or enter your own test identity.</CardDescription>
          <CardAction>
            <Badge variant="outline">local</Badge>
          </CardAction>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4">
            <Field id="email" label="Email" value={props.email} setValue={props.setEmail} testId="email" />
            <Field id="password" label="Password" type="password" value={props.password} setValue={props.setPassword} testId="password" />
            <Field id="name" label="Name" value={props.name} setValue={props.setName} testId="name" />
            <div className="grid gap-2 sm:grid-cols-2">
              <Button type="submit" onClick={props.signUp} data-testid="signup">
                Sign up
                <ArrowRight className="size-4" />
              </Button>
              <Button type="submit" variant="outline" onClick={props.signIn} data-testid="signin">
                Sign in
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </section>
  );
}

function Sidebar(props: {
  displayName: string;
  email: string;
  section: Section;
  setSection: (section: Section) => void;
  signOut: () => void;
}) {
  const items: [Section, typeof Activity, string][] = [
    ["overview", Activity, "Overview"],
    ["settings", Settings, "Settings"],
    ["admin", ShieldCheck, "Admin"],
    ["events", Radio, "Events"],
  ];
  return (
    <aside className="rounded-lg border border-border bg-card p-3">
      <div className="flex items-center gap-3 rounded-lg bg-muted p-3">
        <Avatar className="size-9">
          <AvatarFallback>{initials(props.displayName)}</AvatarFallback>
        </Avatar>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{props.displayName}</div>
          <div className="truncate text-xs text-muted-foreground">{props.email}</div>
        </div>
      </div>
      <nav className="mt-4 grid gap-1 text-sm">
        {items.map(([id, Icon, label]) => (
          <button
            key={id}
            className={`flex h-9 items-center gap-2 rounded-md px-3 text-left ${props.section === id ? "bg-primary text-white" : "text-muted-foreground"}`}
            onClick={() => props.setSection(id)}
          >
            <Icon className="size-4" />
            {label}
          </button>
        ))}
      </nav>
      <Separator className="my-4" />
      <Button variant="outline" className="w-full justify-start" onClick={props.signOut} data-testid="signout">
        <LogOut className="size-4" />
        Sign out
      </Button>
    </aside>
  );
}

function Overview(props: {
  orgs: Organization[];
  sessions: SessionRow[];
  apiKeys: ApiKeyRow[];
  billingCheck: any;
  orgName: string;
  setOrgName: (value: string) => void;
  createOrg: (e: React.FormEvent) => Promise<void>;
}) {
  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <Metric title="Organizations" value={String(props.orgs.length)} icon={Building2} />
        <Metric title="Sessions" value={String(props.sessions.length)} icon={Users} />
        <Metric title="API keys" value={String(props.apiKeys.length)} icon={KeyRound} />
        <Metric title="Billing" value={props.billingCheck?.allowed ? "Allowed" : "Unconfigured"} icon={CreditCard} />
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
        <Card>
          <CardHeader>
            <CardTitle data-testid="signed-in">Workspace access</CardTitle>
            <CardDescription>Organizations are created through the official Better Auth client.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3" data-testid="org-list">
              {props.orgs.length === 0 ? (
                <Empty label="No organizations yet." />
              ) : (
                props.orgs.map((org) => (
                  <Row key={org.id} icon={Building2} title={org.name} detail={`/${org.slug}`} badge={org.role || "member"} />
                ))
              )}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Create organization</CardTitle>
            <CardDescription>Exercise the organization plugin end to end.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-3" onSubmit={props.createOrg}>
              <Field id="org-name" label="Name" value={props.orgName} setValue={props.setOrgName} testId="org-name" />
              <Button type="submit" data-testid="create-org" disabled={!props.orgName.trim()}>
                <Plus className="size-4" />
                Create organization
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

function SettingsPanel(props: {
  session: NonNullable<SessionData>;
  accounts: AccountRow[];
  sessions: SessionRow[];
  apiKeys: ApiKeyRow[];
  apiKeyName: string;
  setApiKeyName: (value: string) => void;
  createApiKey: (e: React.FormEvent) => Promise<void>;
  newApiKey: string | null;
  refreshSettings: () => Promise<void>;
}) {
  return (
    <Tabs defaultValue="profile" className="grid gap-4">
      <TabsList className="w-full justify-start overflow-x-auto">
        <TabsTrigger value="profile">Profile</TabsTrigger>
        <TabsTrigger value="accounts">Accounts</TabsTrigger>
        <TabsTrigger value="sessions">Sessions</TabsTrigger>
        <TabsTrigger value="keys">API keys</TabsTrigger>
        <TabsTrigger value="billing">Billing</TabsTrigger>
      </TabsList>
      <TabsContent value="profile">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
            <CardDescription>Current Better Auth user payload.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <Row icon={UserRound} title={props.session.user.name || "Unnamed"} detail={props.session.user.email} badge="active" />
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="accounts">
        <ListCard title="Linked accounts" description="OAuth and credential accounts linked to this user." rows={props.accounts.map((a) => ({ icon: Link2, title: a.providerId, detail: a.accountId }))} />
      </TabsContent>
      <TabsContent value="sessions">
        <ListCard title="Sessions" description="Active sessions for this user." rows={props.sessions.map((s) => ({ icon: Lock, title: s.current ? "Current session" : "Session", detail: s.userAgent || s.id, badge: s.current ? "current" : undefined }))} />
      </TabsContent>
      <TabsContent value="keys">
        <Card>
          <CardHeader>
            <CardTitle>API keys</CardTitle>
            <CardDescription>Create and list hashed bearer-style API keys.</CardDescription>
            <CardAction>
              <Button variant="outline" onClick={props.refreshSettings}><RefreshCw className="size-4" />Refresh</Button>
            </CardAction>
          </CardHeader>
          <CardContent className="grid gap-4">
            <form className="grid gap-3 sm:grid-cols-[1fr_auto]" onSubmit={props.createApiKey}>
              <Input value={props.apiKeyName} onChange={(e) => props.setApiKeyName(e.target.value)} />
              <Button type="submit"><Plus className="size-4" />Create key</Button>
            </form>
            {props.newApiKey && <div className="rounded-lg bg-muted p-3 font-mono text-xs">{props.newApiKey}</div>}
            <div className="grid gap-3">
              {props.apiKeys.length === 0 ? <Empty label="No API keys yet." /> : props.apiKeys.map((k) => <Row key={k.id} icon={KeyRound} title={k.name || "API key"} detail={k.keyPrefix || k.id} />)}
            </div>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="billing">
        <Card>
          <CardHeader>
            <CardTitle>Billing</CardTitle>
            <CardDescription>Customer billing state is served by the Kernia Stripe plugin.</CardDescription>
          </CardHeader>
        </Card>
      </TabsContent>
    </Tabs>
  );
}

function AdminPanel(props: {
  methods: Record<string, AuthMethod>;
  enabledMethods: [string, AuthMethod][];
  disabledMethods: [string, AuthMethod][];
  toggleMethod: (id: string, enabled: boolean) => Promise<void>;
  emailClients: any[];
  saveDemoEmailClient: () => Promise<void>;
  stripeConfig: any;
  saveDemoStripeConfig: () => Promise<void>;
  products: any[];
  prices: any[];
  syncStripe: () => Promise<void>;
}) {
  return (
    <Tabs defaultValue="methods" className="grid gap-4">
      <TabsList className="w-full justify-start overflow-x-auto">
        <TabsTrigger value="methods">Auth methods</TabsTrigger>
        <TabsTrigger value="email">Emails</TabsTrigger>
        <TabsTrigger value="stripe">Stripe setup</TabsTrigger>
        <TabsTrigger value="catalog">Products & prices</TabsTrigger>
        <TabsTrigger value="usage">Entitlements</TabsTrigger>
      </TabsList>
      <TabsContent value="methods">
        <Card>
          <CardHeader>
            <CardTitle>Active login methods</CardTitle>
            <CardDescription>Persisted method toggles gate the matching auth routes.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            {Object.entries(props.methods).map(([id, method]) => (
              <div key={id} className="flex items-center justify-between rounded-lg border border-border p-3">
                <div>
                  <div className="text-sm font-medium">{method.label || id}</div>
                  <div className="text-xs text-muted-foreground">{id}</div>
                </div>
                <Button variant={method.enabled ? "default" : "outline"} onClick={() => props.toggleMethod(id, !method.enabled)}>
                  {method.enabled ? "Enabled" : "Disabled"}
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="email">
        <Card>
          <CardHeader>
            <CardTitle>Email clients</CardTitle>
            <CardDescription>SMTP, Resend, and Postmark configs share one redacted storage surface.</CardDescription>
            <CardAction><Button onClick={props.saveDemoEmailClient}><Mail className="size-4" />Save Postmark demo</Button></CardAction>
          </CardHeader>
          <CardContent className="grid gap-3">
            {props.emailClients.length === 0 ? <Empty label="No email clients configured." /> : props.emailClients.map((c) => <Row key={c.id} icon={Mail} title={c.id} detail={`${c.kind} · ${c.from}`} badge={c.apiKey} />)}
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="stripe">
        <Card>
          <CardHeader>
            <CardTitle>Stripe setup</CardTitle>
            <CardDescription>Secrets are persisted but redacted on read.</CardDescription>
            <CardAction><Button onClick={props.saveDemoStripeConfig}><CreditCard className="size-4" />Save test config</Button></CardAction>
          </CardHeader>
          <CardContent>
            <pre className="overflow-auto rounded-lg bg-primary p-4 text-xs text-white">{JSON.stringify(props.stripeConfig, null, 2)}</pre>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="catalog">
        <div className="grid gap-4 lg:grid-cols-2">
          <ListCard title="Products" description="Imported from Stripe." action={<Button onClick={props.syncStripe}><RefreshCw className="size-4" />Sync Stripe</Button>} rows={props.products.map((p) => ({ icon: CreditCard, title: p.name, detail: p.stripeProductId, badge: p.active ? "active" : "inactive" }))} />
          <ListCard title="Prices" description="Imported from Stripe." rows={props.prices.map((p) => ({ icon: CreditCard, title: p.lookupKey || p.stripePriceId, detail: `${p.currency} ${p.unitAmount || 0}`, badge: p.interval }))} />
        </div>
      </TabsContent>
      <TabsContent value="usage">
        <Card>
          <CardHeader>
            <CardTitle>Entitlements & usage</CardTitle>
            <CardDescription>Billing checks and usage tracking use Kernia’s Stripe billing tables.</CardDescription>
            <CardAction><Badge variant="outline"><Webhook className="size-3" />webhooks ready</Badge></CardAction>
          </CardHeader>
        </Card>
      </TabsContent>
    </Tabs>
  );
}

function Field(props: { id: string; label: string; value: string; setValue: (value: string) => void; type?: string; testId?: string }) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={props.id}>{props.label}</Label>
      <Input id={props.id} type={props.type || "text"} value={props.value} onChange={(e) => props.setValue(e.target.value)} data-testid={props.testId} />
    </div>
  );
}

function Metric({ title, value, icon: Icon }: { title: string; value: string; icon: typeof Activity }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription className="flex items-center gap-2"><Icon className="size-4" />{title}</CardDescription>
        <CardTitle className="text-2xl">{value}</CardTitle>
      </CardHeader>
    </Card>
  );
}

function Row({ icon: Icon, title, detail, badge }: { icon: typeof Activity; title: string; detail?: string; badge?: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-border p-3">
      <div className="flex min-w-0 items-center gap-3">
        <div className="grid size-9 place-items-center rounded-md bg-secondary text-secondary-foreground"><Icon className="size-4" /></div>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{title}</div>
          {detail && <div className="truncate text-xs text-muted-foreground">{detail}</div>}
        </div>
      </div>
      {badge && <Badge variant="secondary">{badge}</Badge>}
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return <div className="rounded-lg border border-dashed border-border p-5 text-sm text-muted-foreground">{label}</div>;
}

function ListCard({ title, description, rows, action }: { title: string; description: string; rows: { icon: typeof Activity; title: string; detail?: string; badge?: string }[]; action?: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
        {action && <CardAction>{action}</CardAction>}
      </CardHeader>
      <CardContent className="grid gap-3">
        {rows.length === 0 ? <Empty label={`No ${title.toLowerCase()} yet.`} /> : rows.map((row, idx) => <Row key={`${row.title}-${idx}`} {...row} />)}
      </CardContent>
    </Card>
  );
}

function EventsPanel() {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [polling, setPolling] = useState(true);

  useEffect(() => {
    let timer: number | undefined;
    async function tick() {
      try {
        const r = await fetch("/api/demo/events", { credentials: "include" });
        if (r.ok) {
          const data = await r.json();
          setEvents(data.events ?? []);
        }
      } catch {
        // network blip — keep polling
      }
      if (polling) timer = window.setTimeout(tick, 2000);
    }
    tick();
    return () => {
      if (timer) window.clearTimeout(timer);
    };
  }, [polling]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Event bus</CardTitle>
        <CardDescription>
          Live tap of <code>kernia.events</code> from the running server. The Stripe
          plugin subscribes to <code>organization.member.added/removed</code> in its{" "}
          <code>init</code> hook and pushes <code>quantity</code> updates to Stripe
          on every change. Invite or remove a member from the Settings tab — the
          events flow through here in real time.
        </CardDescription>
        <CardAction>
          <Button variant="outline" size="sm" onClick={() => setPolling((p) => !p)}>
            {polling ? "Pause" : "Resume"}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-2">
        {events.length === 0 ? (
          <Empty label="No events captured yet. Try inviting an org member from Settings → Organization." />
        ) : (
          events
            .slice()
            .reverse()
            .map((e, idx) => (
              <div
                key={`${e.event}-${idx}`}
                className="flex items-center justify-between rounded-md border border-border bg-card p-3"
                data-testid="event-row"
              >
                <div className="grid min-w-0 gap-1">
                  <div className="text-sm font-medium">{e.event}</div>
                  <div className="truncate text-xs text-muted-foreground">
                    org <code>{e.organization_id.slice(0, 12)}…</code> · user{" "}
                    <code>{e.user_id.slice(0, 12)}…</code> · role{" "}
                    <Badge variant="outline">{e.role}</Badge>
                  </div>
                </div>
              </div>
            ))
        )}
      </CardContent>
    </Card>
  );
}
