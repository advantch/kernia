/**
 * The OFFICIAL better-auth JavaScript client, pointed at our Python server.
 *
 * The `baseURL` is same-origin because vite proxies /api/* to localhost:8000.
 * That's important: SameSite=Lax cookies don't flow on cross-origin XHR, so a
 * direct cross-origin baseURL would break session persistence on every fetch.
 *
 * If anything wire-protocol-incompatible exists between the Python port and
 * the reference TS server, the official client will surface it here.
 */
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: `${window.location.origin}/api/auth`,
  plugins: [organizationClient()],
});
