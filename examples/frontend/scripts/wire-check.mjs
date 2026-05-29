/**
 * Node-only end-to-end wire-protocol check.
 *
 * Drives the OFFICIAL `better-auth` JS client against the running Python
 * backend. This is the same client a real frontend uses; if any of its
 * `signUp`, `signIn`, `getSession`, `signOut`, `organization.*` calls fail,
 * the wire protocol is broken.
 *
 * Run AFTER both servers are up:
 *     node examples/frontend/scripts/wire-check.mjs
 */

// IMPORTANT: install the cookie-jar fetch BEFORE importing better-auth — its
// client snapshots `globalThis.fetch` at module load time.
const jar = new Map();
const DEBUG = process.env.WIRE_DEBUG === "1";
const origFetch = globalThis.fetch.bind(globalThis);

globalThis.fetch = async (url, init = {}) => {
  const cookieHeader = Array.from(jar.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  const headers = new Headers(init.headers || {});
  if (cookieHeader) headers.set("Cookie", cookieHeader);
  if (DEBUG) console.log(`→ ${init.method || "GET"} ${url}  jar=${jar.size}`);
  const resp = await origFetch(url, { ...init, headers });
  if (DEBUG) console.log(`← ${resp.status}`);
  const setCookies = typeof resp.headers.getSetCookie === "function"
    ? resp.headers.getSetCookie()
    : [];
  for (const sc of setCookies) {
    const [pair] = sc.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) {
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (DEBUG) console.log(`   set ${name}=${value.slice(0, 24)}…`);
      if (value === "" || value === '""') jar.delete(name);
      else jar.set(name, value);
    }
  }
  return resp;
};

// Now safe to import better-auth.
const { createAuthClient } = await import("better-auth/client");
const { organizationClient } = await import("better-auth/client/plugins");

const auth = createAuthClient({
  baseURL: "http://localhost:5050/api/auth",
  plugins: [organizationClient()],
});

const rand = () => Math.random().toString(36).slice(2, 10);
const email = `wire-${rand()}@example.com`;
const password = "correcthorse";

function step(name, ok, detail = "") {
  const tag = ok ? "✓" : "✗";
  console.log(`${tag} ${name}${detail ? "  " + detail : ""}`);
  if (!ok) process.exitCode = 1;
}

console.log("=== Wire check against http://localhost:5050/api/auth ===");

// 1. sign up
{
  const { data, error } = await auth.signUp.email({ email, password, name: "Wire User" });
  step("signUp.email", !error && data?.user?.email === email, error ? JSON.stringify(error) : "");
}

// 2. get session
{
  const { data, error } = await auth.getSession();
  step("getSession (after sign-up)", !error && data?.user?.email === email, error ? JSON.stringify(error) : "");
}

// 3. sign out
{
  const { error } = await auth.signOut();
  step("signOut", !error, error ? JSON.stringify(error) : "");
}

// 4. session is gone
{
  const { data } = await auth.getSession();
  step("getSession (after sign-out → null)", data === null);
}

// 5. sign in
{
  const { data, error } = await auth.signIn.email({ email, password });
  step("signIn.email", !error && data?.user?.email === email, error ? JSON.stringify(error) : "");
}

// 6. create an organization
let orgId;
{
  const slug = `wire-${rand()}`;
  const { data, error } = await auth.organization.create({ name: "Wire Org", slug });
  step("organization.create", !error && data?.id, error ? JSON.stringify(error) : "");
  orgId = data?.id;
}

// 7. list organizations
{
  const { data, error } = await auth.organization.list();
  const ok = !error && Array.isArray(data) && data.some((o) => o.id === orgId);
  step("organization.list contains created org", ok, error ? JSON.stringify(error) : "");
}

// 8. wrong password
{
  await auth.signOut();
  const { error } = await auth.signIn.email({ email, password: "wrongpw" });
  step("signIn.email rejects wrong password", !!error, error ? error.code : "");
}

console.log(process.exitCode ? "\nFAIL" : "\nOK — wire protocol matches better-auth client expectations");
