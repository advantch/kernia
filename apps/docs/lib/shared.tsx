import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import { Github, LockKeyhole, Menu, Search } from "lucide-react";

export const appName = "Kernia";
export const docsRoute = "/docs";
export const docsImageRoute = "/og/docs";
export const docsContentRoute = "/llms.mdx/docs";

export const gitConfig = {
  user: "advantch",
  repo: "kernia",
  branch: "feat/kernia-rebrand-parity"
};

export function KerniaMark({ className = "size-8" }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" aria-hidden="true" className={className}>
      <defs>
        <linearGradient id="kernia-mark" x1="10" x2="54" y1="8" y2="58">
          <stop stopColor="#34d399" />
          <stop offset="0.55" stopColor="#10b981" />
          <stop offset="1" stopColor="#0f766e" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="18" fill="#071411" />
      <path
        d="M22 19c8-7 23-3 24 8 1 8-7 12-15 12h-4c-4 0-6 2-6 5 0 4 5 7 11 7 4 0 8-1 11-3"
        fill="none"
        stroke="url(#kernia-mark)"
        strokeLinecap="round"
        strokeWidth="6"
      />
      <path
        d="M25 34v-5c0-5 3-9 8-9s8 4 8 9v5"
        fill="none"
        stroke="#d1fae5"
        strokeLinecap="round"
        strokeWidth="4"
      />
      <rect x="21" y="32" width="24" height="18" rx="5" fill="#ecfdf5" />
      <circle cx="33" cy="41" r="3" fill="#065f46" />
      <path d="M33 43v4" stroke="#065f46" strokeLinecap="round" strokeWidth="2" />
      <circle cx="42" cy="27" r="2" fill="#ecfdf5" />
    </svg>
  );
}

export function LogoTitle() {
  return (
    <span className="flex items-center gap-2 font-semibold">
      <KerniaMark className="size-7" />
      <span>Kernia</span>
    </span>
  );
}

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: <LogoTitle />,
      transparentMode: "top"
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      {
        text: "Docs",
        url: "/docs",
        active: "nested-url"
      },
      {
        text: "Demo",
        url: "/docs/examples/fastapi-saas-demo"
      },
      {
        text: "GitHub",
        url: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
        icon: <Github className="size-4" />,
        external: true
      }
    ]
  };
}

export const homeCards = [
  {
    title: "Better Auth-compatible",
    body: "Preserves the route, cookie, and JSON contracts expected by the official Better Auth JavaScript client.",
    icon: <LockKeyhole className="size-5" />
  },
  {
    title: "Python-native",
    body: "FastAPI, Starlette, Django, SQLAlchemy, Mongo, Redis storage, and a Python package family under kernia.* names.",
    icon: <Menu className="size-5" />
  },
  {
    title: "SaaS-ready",
    body: "Organizations, admin config, API keys, Stripe billing, entitlements, sessions, passkeys, SSO, SCIM, and OpenAPI.",
    icon: <Search className="size-5" />
  }
];
