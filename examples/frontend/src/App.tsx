import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  Building2,
  CheckCircle2,
  KeyRound,
  LogOut,
  Plus,
  ShieldCheck,
  Sparkles,
  Users,
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
type Organization = {
  id: string;
  name: string;
  slug: string;
  role?: string;
};

const defaultEmail = "founder@acme.test";
const defaultPassword = "correcthorse";

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
  const [session, setSession] = useState<SessionData>(null);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState(defaultEmail);
  const [password, setPassword] = useState(defaultPassword);
  const [name, setName] = useState("Avery Stone");
  const [error, setError] = useState<string | null>(null);
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [orgName, setOrgName] = useState("Acme Workspace");

  const activeOrg = orgs[0];
  const displayName = session?.user.name || session?.user.email || "Operator";

  const auditRows = useMemo(
    () => [
      { label: "Session cookie", value: session ? "Active" : "Pending" },
      { label: "Auth client", value: "better-auth@1.6.11" },
      { label: "Backend", value: "FastAPI /api/auth" },
    ],
    [session],
  );

  async function refresh() {
    const { data } = await authClient.getSession();
    setSession(data);
    setLoading(false);
    if (data) await refreshOrgs();
  }

  async function refreshOrgs() {
    const { data } = await authClient.organization.list();
    setOrgs(Array.isArray(data) ? (data as Organization[]) : []);
  }

  useEffect(() => {
    refresh();
  }, []);

  async function signUp(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const { error: err } = await authClient.signUp.email({
      email,
      password,
      name: name || email.split("@")[0],
    });
    if (err) setError(err.message || String(err.code));
    else await refresh();
  }

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const { error: err } = await authClient.signIn.email({ email, password });
    if (err) setError(err.message || String(err.code));
    else await refresh();
  }

  async function signOut() {
    await authClient.signOut();
    setSession(null);
    setOrgs([]);
  }

  async function createOrg(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const slug = slugify(orgName);
    const { error: err } = await authClient.organization.create({
      name: orgName,
      slug,
    });
    if (err) setError(err.message || String(err.code));
    else {
      setOrgName("");
      await refreshOrgs();
    }
  }

  if (loading) {
    return (
      <main className="grid min-h-screen place-items-center bg-[#f7f7f4] px-4">
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
    <main className="min-h-screen bg-[#f7f7f4] text-[#1f2933]">
      <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col px-4 py-4 sm:px-6 lg:px-8">
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-[#dfded7]">
          <div className="flex items-center gap-3">
            <div className="grid size-8 place-items-center rounded-lg bg-[#1f2933] text-white">
              <ShieldCheck className="size-4" />
            </div>
            <div>
              <div className="text-sm font-semibold leading-none">Kernia</div>
              <div className="mt-1 text-xs text-[#68717d]">SaaS control plane</div>
            </div>
          </div>
          <Badge variant="outline" className="hidden gap-1 border-[#c9d8ce] bg-[#eef6f1] sm:inline-flex">
            <CheckCircle2 className="size-3" />
            FastAPI live
          </Badge>
        </header>

        {error && (
          <div
            className="mt-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
            data-testid="error"
          >
            {error}
          </div>
        )}

        {session ? (
          <section className="grid flex-1 gap-4 py-4 lg:grid-cols-[260px_minmax(0,1fr)]">
            <aside className="rounded-lg border border-[#dfded7] bg-white p-3">
              <div className="flex items-center gap-3 rounded-lg bg-[#f3f2ee] p-3">
                <Avatar className="size-9">
                  <AvatarFallback>{initials(displayName)}</AvatarFallback>
                </Avatar>
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{displayName}</div>
                  <div className="truncate text-xs text-[#68717d]">{session.user.email}</div>
                </div>
              </div>
              <nav className="mt-4 grid gap-1 text-sm">
                <button className="flex h-9 items-center gap-2 rounded-md bg-[#1f2933] px-3 text-left text-white">
                  <Activity className="size-4" />
                  Overview
                </button>
                <button className="flex h-9 items-center gap-2 rounded-md px-3 text-left text-[#4d5966]">
                  <Building2 className="size-4" />
                  Workspaces
                </button>
                <button className="flex h-9 items-center gap-2 rounded-md px-3 text-left text-[#4d5966]">
                  <KeyRound className="size-4" />
                  Sessions
                </button>
              </nav>
              <Separator className="my-4" />
              <Button variant="outline" className="w-full justify-start" onClick={signOut} data-testid="signout">
                <LogOut className="size-4" />
                Sign out
              </Button>
            </aside>

            <div className="grid content-start gap-4">
              <div className="grid gap-4 md:grid-cols-3">
                <Card size="sm">
                  <CardHeader>
                    <CardDescription>Active organizations</CardDescription>
                    <CardTitle className="text-2xl">{orgs.length}</CardTitle>
                  </CardHeader>
                </Card>
                <Card size="sm">
                  <CardHeader>
                    <CardDescription>Session state</CardDescription>
                    <CardTitle className="text-2xl">Verified</CardTitle>
                  </CardHeader>
                </Card>
                <Card size="sm">
                  <CardHeader>
                    <CardDescription>Protocol check</CardDescription>
                    <CardTitle className="text-2xl">JS client</CardTitle>
                  </CardHeader>
                </Card>
              </div>

              <Tabs defaultValue="workspace" className="grid gap-4">
                <TabsList className="w-full justify-start sm:w-fit">
                  <TabsTrigger value="workspace">Workspace</TabsTrigger>
                  <TabsTrigger value="audit">Audit</TabsTrigger>
                </TabsList>

                <TabsContent value="workspace" className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
                  <Card>
                    <CardHeader>
                      <CardTitle data-testid="signed-in">Workspace access</CardTitle>
                      <CardDescription>
                        Signed in as {session.user.email}; organization calls use the official Better Auth client.
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid gap-3" data-testid="org-list">
                        {orgs.length === 0 ? (
                          <div className="rounded-lg border border-dashed border-[#cfd3d8] p-5 text-sm text-[#68717d]">
                            No organizations yet.
                          </div>
                        ) : (
                          orgs.map((org) => (
                            <div
                              key={org.id}
                              className="flex items-center justify-between rounded-lg border border-[#e1e3e6] p-3"
                            >
                              <div className="flex min-w-0 items-center gap-3">
                                <div className="grid size-9 place-items-center rounded-md bg-[#edf3ff] text-[#315f9f]">
                                  <Building2 className="size-4" />
                                </div>
                                <div className="min-w-0">
                                  <div className="truncate text-sm font-medium">{org.name}</div>
                                  <div className="truncate text-xs text-[#68717d]">/{org.slug}</div>
                                </div>
                              </div>
                              <Badge variant="secondary">{org.role || "member"}</Badge>
                            </div>
                          ))
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Create organization</CardTitle>
                      <CardDescription>Exercise the organization plugin through the JS client.</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <form className="grid gap-3" onSubmit={createOrg}>
                        <div className="grid gap-2">
                          <Label htmlFor="org-name">Name</Label>
                          <Input
                            id="org-name"
                            placeholder="Acme Workspace"
                            value={orgName}
                            onChange={(e) => setOrgName(e.target.value)}
                            data-testid="org-name"
                          />
                        </div>
                        <Button type="submit" data-testid="create-org" disabled={!orgName.trim()}>
                          <Plus className="size-4" />
                          Create organization
                        </Button>
                      </form>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="audit">
                  <Card>
                    <CardHeader>
                      <CardTitle>Runtime proof</CardTitle>
                      <CardDescription>What this browser session is currently exercising.</CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-3">
                      {auditRows.map((row) => (
                        <div key={row.label} className="flex items-center justify-between rounded-lg bg-[#f7f7f4] px-3 py-2">
                          <span className="text-sm text-[#68717d]">{row.label}</span>
                          <span className="text-sm font-medium">{row.value}</span>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </div>
          </section>
        ) : (
          <section className="grid flex-1 items-center gap-6 py-8 lg:grid-cols-[minmax(0,1fr)_420px]">
            <div className="max-w-2xl">
              <Badge className="mb-4 gap-1 bg-[#e7f2ff] text-[#244b78]" variant="secondary">
                <Sparkles className="size-3" />
                Kernia + Better Auth JS client
              </Badge>
              <h1 className="max-w-xl text-4xl font-semibold tracking-normal text-[#1f2933] sm:text-5xl">
                SaaS auth running on FastAPI.
              </h1>
              <p className="mt-4 max-w-xl text-base leading-7 text-[#5e6975]">
                This demo signs up a user, persists the session cookie, creates an organization, and reads it back through the official Better Auth client.
              </p>
              <div className="mt-6 grid gap-3 sm:grid-cols-3">
                {[
                  ["Email auth", "signUp.email + signIn.email"],
                  ["Sessions", "getSession + signOut"],
                  ["Organizations", "create + list"],
                ].map(([title, body]) => (
                  <div key={title} className="rounded-lg border border-[#dfded7] bg-white p-4">
                    <div className="text-sm font-medium">{title}</div>
                    <div className="mt-1 text-xs leading-5 text-[#68717d]">{body}</div>
                  </div>
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
                  <div className="grid gap-2">
                    <Label htmlFor="email">Email</Label>
                    <Input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      data-testid="email"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="password">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      data-testid="password"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="name">Name</Label>
                    <Input
                      id="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      data-testid="name"
                    />
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    <Button type="submit" onClick={signUp} data-testid="signup">
                      Sign up
                      <ArrowRight className="size-4" />
                    </Button>
                    <Button type="submit" variant="outline" onClick={signIn} data-testid="signin">
                      Sign in
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </section>
        )}
      </div>
    </main>
  );
}
