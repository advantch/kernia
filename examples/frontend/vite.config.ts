import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Proxy /api/* to the Python backend so the browser sees same-origin requests.
// SameSite=Lax cookies (the better-auth default) don't flow on cross-origin XHR,
// so without this proxy the session cookie would never make it back to the
// server on a subsequent fetch. Production typically uses a similar pattern
// (a reverse proxy / Next.js rewrites / nginx).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://localhost:5050",
        changeOrigin: true,
      },
    },
  },
});
