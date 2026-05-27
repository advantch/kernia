import { useEffect, useState } from "react";
import { authClient } from "./auth-client";

type SessionData = Awaited<ReturnType<typeof authClient.getSession>>["data"];

const box: React.CSSProperties = {
  fontFamily: "system-ui, -apple-system, sans-serif",
  maxWidth: 560,
  margin: "40px auto",
  padding: 24,
  border: "1px solid #ddd",
  borderRadius: 8,
};

const input: React.CSSProperties = {
  display: "block",
  width: "100%",
  padding: 8,
  marginBottom: 8,
  border: "1px solid #ccc",
  borderRadius: 4,
  fontSize: 14,
  boxSizing: "border-box",
};

const button: React.CSSProperties = {
  padding: "8px 14px",
  marginRight: 8,
  marginTop: 4,
  background: "#0066ff",
  color: "white",
  border: "none",
  borderRadius: 4,
  cursor: "pointer",
};

export function App() {
  const [session, setSession] = useState<SessionData>(null);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [orgs, setOrgs] = useState<any[]>([]);
  const [orgName, setOrgName] = useState("");

  async function refresh() {
    const { data } = await authClient.getSession();
    setSession(data);
    setLoading(false);
    if (data) await refreshOrgs();
  }

  async function refreshOrgs() {
    const { data } = await authClient.organization.list();
    setOrgs(Array.isArray(data) ? data : []);
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
    const slug = orgName.toLowerCase().replace(/\s+/g, "-");
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

  if (loading) return <div style={box}>Loading…</div>;

  return (
    <div style={box}>
      <h1 style={{ marginTop: 0 }}>kernia demo</h1>
      <p style={{ color: "#666", fontSize: 13 }}>
        React + official <code>better-auth</code> JS client talking to a Python
        FastAPI server.
      </p>

      {error && (
        <div
          style={{
            background: "#ffe6e6",
            color: "#a00",
            padding: 8,
            borderRadius: 4,
            marginBottom: 12,
            fontSize: 13,
          }}
          data-testid="error"
        >
          {error}
        </div>
      )}

      {session ? (
        <>
          <h2 data-testid="signed-in">
            Signed in as {session.user.email}
          </h2>
          <p style={{ color: "#666" }}>
            user id: <code>{session.user.id}</code>
          </p>
          <button onClick={signOut} style={button} data-testid="signout">
            Sign out
          </button>

          <h3>Your organizations</h3>
          <ul data-testid="org-list">
            {orgs.length === 0 && <li style={{ color: "#888" }}>none yet</li>}
            {orgs.map((o) => (
              <li key={o.id}>
                {o.name} <small style={{ color: "#888" }}>/{o.slug}</small>
              </li>
            ))}
          </ul>

          <form onSubmit={createOrg}>
            <input
              style={input}
              placeholder="New organization name"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              data-testid="org-name"
            />
            <button type="submit" style={button} data-testid="create-org">
              Create organization
            </button>
          </form>
        </>
      ) : (
        <>
          <h2>Sign up / sign in</h2>
          <form>
            <input
              style={input}
              type="email"
              placeholder="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              data-testid="email"
            />
            <input
              style={input}
              type="password"
              placeholder="password (min 8 chars)"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              data-testid="password"
            />
            <input
              style={input}
              type="text"
              placeholder="name (sign-up only)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="name"
            />
            <button onClick={signUp} style={button} data-testid="signup">
              Sign up
            </button>
            <button onClick={signIn} style={button} data-testid="signin">
              Sign in
            </button>
          </form>
        </>
      )}
    </div>
  );
}
