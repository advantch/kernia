/**
 * The OFFICIAL better-auth JavaScript client, pointed at our Python server.
 *
 * The client validates `baseURL` as an absolute URL, so we give it
 * `window.location.origin + "/api/auth"`. The vite dev proxy (see
 * vite.config.ts) forwards `/api/*` to the Python backend on :5050 — the
 * browser still sees same-origin requests so `SameSite=Lax` cookies flow.
 *
 * If anything wire-protocol-incompatible exists between the Python port and
 * the reference TS server, the official client will surface it here.
 */
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

const baseURL =
  typeof window !== "undefined"
    ? `${window.location.origin}/api/auth`
    : "http://localhost:5173/api/auth";

export const authClient = createAuthClient({
  baseURL: `${window.location.origin}/api/auth`,
  plugins: [organizationClient()],
});
