"use client";

import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { cn } from "@/lib/utils";
import { TrustedBy } from "./trusted-by";

type InstallMode = "cli" | "prompt" | "server" | "client";

const tabs: { id: InstallMode; label: string }[] = [
  { id: "cli", label: "CLI" },
  { id: "prompt", label: "Prompt" },
  { id: "server", label: "Server" },
  { id: "client", label: "Client" },
];

const cliCommand = "uv add kernia kernia-cli kernia-fastapi kernia-sqlalchemy";

const serverCode = `import os

from kernia import KerniaOptions
from kernia.auth import init
from kernia.plugins.organization import organization
from kernia.types.init_options import EmailPasswordOptions
from kernia_fastapi import mount_kernia

auth = init(KerniaOptions(
    database=adapter,
    secret=os.environ["KERNIA_SECRET"],
    base_url=os.environ["KERNIA_BASE_URL"],
    email_and_password=EmailPasswordOptions(enabled=True),
    plugins=(organization(),),
))

mount_kernia(app, auth)`;

const clientCode = `await fetch("http://localhost:8000/api/auth/sign-in/email", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ email, password }),
});`;

const promptText = `Set up authentication in my Python project using Kernia.

1. Install kernia, kernia-cli, and the framework package for this app.

2. Create auth.py and call init() with:
   - my existing database connection if one exists
   - email/password enabled
   - organization support if this is a SaaS app
   - OAuth providers only when credentials exist in the environment

3. Mount the auth routes for my framework:
   - FastAPI or Starlette: mount_kernia(app, auth)
   - Django: use the Kernia Django integration

4. Add KERNIA_SECRET to my .env if it does not exist.

5. Run kernia generate and kernia migrate.

6. Keep Python imports under kernia.* and use the documented browser API calls from the demo.`;

const copyByMode: Record<InstallMode, string> = {
  cli: cliCommand,
  prompt: promptText,
  server: serverCode,
  client: clientCode,
};

function CopyIcon({ copied }: { copied: boolean }) {
  if (copied) {
    return (
      <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
        <path
          fill="currentColor"
          d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"
        />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
      <path
        fill="currentColor"
        d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2m0 16H8V7h11z"
      />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
      <path
        fill="currentColor"
        d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"
      />
    </svg>
  );
}

function EyeIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-3 w-3" aria-hidden="true">
      <path
        fill="currentColor"
        d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5M12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5m0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3"
      />
    </svg>
  );
}

function CredentialFields() {
  const emailText = "founder@kernia.dev";
  const passwordDots = "••••••••";
  const [emailDisplay, setEmailDisplay] = useState(emailText);
  const [passwordDisplay, setPasswordDisplay] = useState(passwordDots);
  const [isTyping, setIsTyping] = useState(false);
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const isTypingRef = useRef(false);

  const startTyping = useCallback(() => {
    if (isTypingRef.current) return;
    isTypingRef.current = true;
    setIsTyping(true);

    for (const timeout of timeoutsRef.current) clearTimeout(timeout);
    timeoutsRef.current = [];

    setEmailDisplay("");
    setPasswordDisplay("");

    for (let i = 0; i <= emailText.length; i += 1) {
      const timeout = setTimeout(() => {
        setEmailDisplay(emailText.slice(0, i));
      }, i * 45);
      timeoutsRef.current.push(timeout);
    }

    const passwordStart = (emailText.length + 2) * 45;
    for (let i = 0; i <= passwordDots.length; i += 1) {
      const timeout = setTimeout(
        () => {
          setPasswordDisplay(passwordDots.slice(0, i));
          if (i === passwordDots.length) {
            isTypingRef.current = false;
            setIsTyping(false);
          }
        },
        passwordStart + i * 45,
      );
      timeoutsRef.current.push(timeout);
    }
  }, []);

  useEffect(() => {
    return () => {
      for (const timeout of timeoutsRef.current) clearTimeout(timeout);
    };
  }, []);

  return (
    <div className="mt-3 flex items-center gap-1.5" onMouseEnter={startTyping}>
      <div className="flex h-5 min-w-0 flex-1 items-center border border-foreground/[0.08] bg-foreground/[0.02] px-2">
        <span className="mr-1.5 shrink-0 text-[9px] text-foreground/35">@</span>
        <span className="truncate font-mono text-[9px] text-foreground/50 dark:text-foreground/35">
          {emailDisplay}
          {isTyping && emailDisplay.length < emailText.length && (
            <span className="ml-px inline-block h-2.5 w-px animate-blink bg-foreground/50 align-middle" />
          )}
        </span>
      </div>
      <div className="flex h-5 min-w-0 flex-1 items-center border border-foreground/[0.08] bg-foreground/[0.02] px-2">
        <span className="mr-1.5 shrink-0 text-[9px] text-foreground/35">#</span>
        <span className="font-mono text-[9px] tracking-[0.1em] text-foreground/50 dark:text-foreground/35">
          {passwordDisplay}
          {isTyping &&
            emailDisplay.length >= emailText.length &&
            passwordDisplay.length < passwordDots.length && (
              <span className="ml-px inline-block h-2.5 w-px animate-blink bg-foreground/50 align-middle" />
            )}
        </span>
      </div>
    </div>
  );
}

function SyntaxCommand() {
  return (
    <code
      className="truncate text-[13px]"
      style={{ fontFamily: "var(--font-geist-pixel-square)" }}
    >
      <span className="text-purple-600/90 dark:text-purple-400/90">uv</span>{" "}
      <span className="text-neutral-700 dark:text-neutral-300">add</span>{" "}
      <span className="text-emerald-600/90 dark:text-emerald-400/90">
        kernia
      </span>{" "}
      <span className="text-emerald-600/90 dark:text-emerald-400/90">
        kernia-cli
      </span>{" "}
      <span className="text-emerald-600/90 dark:text-emerald-400/90">
        kernia-fastapi
      </span>{" "}
      <span className="text-emerald-600/90 dark:text-emerald-400/90">
        kernia-sqlalchemy
      </span>
    </code>
  );
}

function ServerSnippet() {
  return (
    <pre className="overflow-x-auto px-4 py-3 text-[12px] leading-6 text-neutral-700 dark:text-neutral-300">
      <code>
        <span className="text-purple-600 dark:text-purple-400">import</span>{" "}
        <span>os</span>
        {"\n\n"}
        <span className="text-purple-600 dark:text-purple-400">from</span>{" "}
        <span className="text-sky-700 dark:text-sky-300">kernia</span>{" "}
        <span className="text-purple-600 dark:text-purple-400">import</span>{" "}
        <span>KerniaOptions</span>
        {"\n"}
        <span className="text-purple-600 dark:text-purple-400">from</span>{" "}
        <span className="text-sky-700 dark:text-sky-300">kernia.auth</span>{" "}
        <span className="text-purple-600 dark:text-purple-400">import</span>{" "}
        <span>init</span>
        {"\n"}
        <span className="text-purple-600 dark:text-purple-400">from</span>{" "}
        <span className="text-sky-700 dark:text-sky-300">kernia_fastapi</span>{" "}
        <span className="text-purple-600 dark:text-purple-400">import</span>{" "}
        <span>mount_kernia</span>
        {"\n\n"}
        <span className="text-neutral-900 dark:text-neutral-100">auth</span>{" "}
        <span className="text-neutral-400">=</span>{" "}
        <span className="text-amber-700 dark:text-amber-300">init</span>
        <span>(</span>
        <span className="text-amber-700 dark:text-amber-300">
          KerniaOptions
        </span>
        <span>(</span>
        {"\n"}
        {"    "}
        <span>database</span>
        <span className="text-neutral-400">=</span>
        <span>adapter</span>
        <span>,</span>
        {"\n"}
        {"    "}
        <span>secret</span>
        <span className="text-neutral-400">=</span>
        <span>os.environ[</span>
        <span className="text-emerald-700 dark:text-emerald-300">
          "KERNIA_SECRET"
        </span>
        <span>]</span>
        <span>,</span>
        {"\n"}
        <span>))</span>
        {"\n\n"}
        <span className="text-amber-700 dark:text-amber-300">mount_kernia</span>
        <span>(app, auth)</span>
      </code>
    </pre>
  );
}

function ClientSnippet() {
  return (
    <pre className="overflow-x-auto px-4 py-3 text-[12px] leading-6 text-neutral-700 dark:text-neutral-300">
      <code>
        <span className="text-purple-600 dark:text-purple-400">await</span>{" "}
        <span className="text-amber-700 dark:text-amber-300">fetch</span>
        <span>(</span>
        <span className="text-emerald-700 dark:text-emerald-300">
          "http://localhost:8000/api/auth/sign-in/email"
        </span>
        <span>, {"{"}</span>
        {"\n"}
        {"  "}
        <span>method</span>
        <span>: </span>
        <span className="text-emerald-700 dark:text-emerald-300">
          "POST"
        </span>
        <span>,</span>
        {"\n"}
        {"  "}
        <span>headers</span>
        <span>: {"{ "}</span>
        <span className="text-emerald-700 dark:text-emerald-300">
          "content-type"
        </span>
        <span>: </span>
        <span className="text-emerald-700 dark:text-emerald-300">
          "application/json"
        </span>
        <span>{" }"}</span>
        <span>,</span>
        {"\n"}
        {"  "}
        <span>body</span>
        <span>: </span>
        <span>JSON.stringify({"{ email, password }"})</span>
        <span>,</span>
        {"\n"}
        <span>{"});"}</span>
      </code>
    </pre>
  );
}

function PromptPreview({
  copied,
  onCopy,
  onOpen,
}: {
  copied: boolean;
  onCopy: () => void;
  onOpen: () => void;
}) {
  return (
    <div className="bg-neutral-100/50 px-5 py-4 dark:bg-[#050505]">
      <p className="text-[13px] font-medium leading-relaxed text-neutral-700 dark:text-neutral-200">
        Set up authentication in my Python project using Kernia.
      </p>
      <div className="relative mt-1.5">
        <p className="max-h-11 overflow-hidden text-[11px] leading-relaxed text-neutral-400 dark:text-neutral-500">
          Install the package, reuse my database, create auth.py with init(),
          mount framework routes, add KERNIA_SECRET, then generate and run
          migrations.
        </p>
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-6 bg-gradient-to-t from-neutral-100/50 to-transparent dark:from-[#050505]" />
      </div>
      <div className="mt-3 flex items-center justify-between border-t border-foreground/[0.04] pt-2">
        <button
          type="button"
          onClick={onOpen}
          className="flex items-center gap-1 text-[11px] text-neutral-400 transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300"
        >
          <EyeIcon />
          View full prompt
        </button>
        <button
          type="button"
          onClick={onCopy}
          className="flex items-center gap-1.5 text-[11px] text-neutral-400 transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300"
        >
          <CopyIcon copied={copied} />
          {copied ? "Copied" : "Copy prompt"}
        </button>
      </div>
    </div>
  );
}

function InstallBlock() {
  const [mode, setMode] = useState<InstallMode>("cli");
  const [copied, setCopied] = useState(false);
  const [promptOpen, setPromptOpen] = useState(false);
  const contentRef = useRef<HTMLDivElement>(null);
  const [contentHeight, setContentHeight] = useState<number | "auto">("auto");
  const [overflow, setOverflow] = useState<"hidden" | "visible">("visible");

  useEffect(() => {
    const element = contentRef.current;
    if (!element) return undefined;

    const resizeObserver = new ResizeObserver(() => {
      setContentHeight(element.offsetHeight);
    });

    resizeObserver.observe(element);
    return () => resizeObserver.disconnect();
  }, []);

  useLayoutEffect(() => {
    setOverflow("hidden");
  }, [mode]);

  const copy = (text = copyByMode[mode]) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="relative mb-6 rounded-md border border-foreground/[0.1]">
      <div className="flex items-center border-b border-foreground/[0.1]">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => {
              setMode(tab.id);
              setCopied(false);
            }}
            className={cn(
              "relative px-4 py-2 text-[12px] transition-colors duration-150",
              mode === tab.id
                ? "text-neutral-800 dark:text-neutral-200"
                : "text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-400",
            )}
          >
            {tab.label}
            {mode === tab.id && (
              <span className="absolute bottom-0 left-4 right-4 h-[1.5px] bg-neutral-600 dark:bg-neutral-400" />
            )}
          </button>
        ))}
      </div>

      <motion.div
        animate={{ height: contentHeight }}
        initial={false}
        onAnimationComplete={() => setOverflow("visible")}
        style={{ overflow }}
        transition={{ duration: 0.3, ease: [0.25, 0.1, 0.25, 1] }}
      >
        <div ref={contentRef}>
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={mode}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18 }}
            >
              {mode === "cli" && (
                <div className="flex items-center justify-between gap-3 bg-neutral-100/50 px-4 py-3 dark:bg-[#050505]">
                  <SyntaxCommand />
                  <button
                    type="button"
                    onClick={() => copy(cliCommand)}
                    className="shrink-0 p-1 text-neutral-400 transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300"
                    aria-label="Copy command"
                  >
                    <CopyIcon copied={copied} />
                  </button>
                </div>
              )}
              {mode === "prompt" && (
                <PromptPreview
                  copied={copied}
                  onCopy={() => copy(promptText)}
                  onOpen={() => setPromptOpen(true)}
                />
              )}
              {mode === "server" && (
                <div className="bg-neutral-100/50 dark:bg-[#050505]">
                  <div className="flex items-center justify-between border-b border-foreground/[0.06] px-4 py-2">
                    <span className="font-mono text-[11px] text-neutral-400">
                      auth.py
                    </span>
                    <button
                      type="button"
                      onClick={() => copy(serverCode)}
                      className="p-1 text-neutral-400 transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300"
                      aria-label="Copy server example"
                    >
                      <CopyIcon copied={copied} />
                    </button>
                  </div>
                  <ServerSnippet />
                </div>
              )}
              {mode === "client" && (
                <div className="bg-neutral-100/50 dark:bg-[#050505]">
                  <div className="flex items-center justify-between border-b border-foreground/[0.06] px-4 py-2">
                    <span className="font-mono text-[11px] text-neutral-400">
                      auth-client.ts
                    </span>
                    <button
                      type="button"
                      onClick={() => copy(clientCode)}
                      className="p-1 text-neutral-400 transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300"
                      aria-label="Copy client example"
                    >
                      <CopyIcon copied={copied} />
                    </button>
                  </div>
                  <ClientSnippet />
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </motion.div>

      <AnimatePresence>
        {promptOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 flex items-center justify-center lg:left-[40%]"
            onClick={() => setPromptOpen(false)}
          >
            <div className="absolute inset-0 bg-black/50 backdrop-blur-sm dark:bg-black/70" />
            <motion.div
              initial={{ opacity: 0, scale: 0.98, y: 8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98, y: 8 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              onClick={(event) => event.stopPropagation()}
              className="relative mx-4 w-[calc(100%-2rem)] max-w-lg rounded-sm border border-neutral-200 bg-neutral-50 shadow-2xl dark:border-white/[0.06] dark:bg-[#0a0a0a]"
            >
              <button
                type="button"
                onClick={() => setPromptOpen(false)}
                className="absolute right-3 top-3 z-10 text-neutral-400 transition-colors hover:text-neutral-600 dark:hover:text-neutral-300"
                aria-label="Close prompt"
              >
                <CloseIcon />
              </button>
              <div className="max-h-[60vh] overflow-y-auto px-5 py-5">
                <p className="whitespace-pre-line font-mono text-[12px] leading-[1.9] text-neutral-600 dark:text-neutral-400">
                  {promptText}
                </p>
              </div>
              <div className="flex justify-end border-t border-neutral-200 px-5 py-3 dark:border-white/[0.06]">
                <button
                  type="button"
                  onClick={() => copy(promptText)}
                  className="flex items-center gap-1.5 rounded-sm border border-neutral-200 px-3 py-1.5 text-[11px] text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:border-white/[0.08] dark:text-neutral-400 dark:hover:bg-white/[0.04] dark:hover:text-neutral-200"
                >
                  <CopyIcon copied={copied} />
                  {copied ? "Copied" : "Copy prompt"}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

const providerIcons = ["Google", "GitHub", "Apple", "Discord"];

const features = [
  {
    label: "Frameworks",
    headline: "Works with your Python stack.",
    desc: "FastAPI, Starlette, Django, and browser clients.",
    href: "/docs/integrations/fastapi",
    kind: "frameworks",
  },
  {
    label: "Email & password",
    headline: "Credential auth included.",
    desc: "Sessions, verification, reset flows, and account linking.",
    href: "/docs/authentication/email-password",
    kind: "credentials",
  },
  {
    label: "Social sign-on",
    headline: "OAuth providers.",
    desc: "Google, GitHub, Apple, Discord, Slack, and custom OAuth.",
    href: "/docs/authentication/google",
    kind: "social",
  },
  {
    label: "Organizations",
    headline: "Multi-tenant SaaS.",
    desc: "Teams, roles, invitations, members, and active org context.",
    href: "/docs/plugins/organization",
    kind: "org",
  },
  {
    label: "Admin",
    headline: "Runtime configuration.",
    desc: "Login methods, email clients, provider status, and admin policy.",
    href: "/docs/plugins/admin-config",
    kind: "admin",
  },
  {
    label: "Plugins",
    headline: "Auth surface area.",
    desc: "API keys, passkeys, SSO, SCIM, MFA, JWT, bearer, SIWE, and more.",
    href: "/docs/plugins",
    kind: "plugins",
  },
  {
    label: "MCP",
    headline: "Agent authorization.",
    desc: "MCP tokens and OAuth-style agent authorization routes.",
    href: "/docs/plugins/mcp",
    kind: "mcp",
  },
  {
    label: "Stripe",
    headline: "SaaS revenue flows.",
    desc: "Checkout, portal, webhooks, catalog sync, entitlements, and usage.",
    href: "/docs/plugins/stripe",
    kind: "stripe",
  },
  {
    label: "Demo",
    headline: "Reference SaaS app.",
    desc: "Login, settings, sessions, accounts, API keys, admin, and usage.",
    href: "/docs/examples/fastapi-saas-demo",
    kind: "demo",
  },
];

function FeatureVisual({ kind }: { kind: string }) {
  if (kind === "frameworks") {
    return (
      <div className="mt-3 flex flex-wrap gap-1.5">
        {["FastAPI", "Starlette", "Django", "+JS"].map((item) => (
          <span
            key={item}
            className="border border-foreground/[0.08] px-1.5 py-0.5 font-mono text-[8px] text-foreground/45"
          >
            {item}
          </span>
        ))}
      </div>
    );
  }

  if (kind === "credentials") return <CredentialFields />;

  if (kind === "social") {
    return (
      <div className="mt-3 flex items-center gap-2">
        {providerIcons.map((provider) => (
          <div
            key={provider}
            className="flex size-6 items-center justify-center border border-foreground/[0.08] bg-background font-mono text-[8px] text-foreground/50 opacity-70 transition-opacity group-hover/card:opacity-100"
          >
            {provider.slice(0, 1)}
          </div>
        ))}
      </div>
    );
  }

  if (kind === "admin") {
    return (
      <div className="mt-3 space-y-1.5">
        {["email", "oauth", "passkey"].map((item, index) => (
          <div key={item} className="flex items-center justify-between">
            <span className="font-mono text-[8px] text-foreground/40">
              {item}
            </span>
            <span
              className={cn(
                "h-2 w-5 border border-foreground/[0.12]",
                index === 1 ? "bg-foreground/20" : "bg-emerald-500/40",
              )}
            />
          </div>
        ))}
      </div>
    );
  }

  if (kind === "org") {
    return (
      <div className="mt-3 flex -space-x-1">
        {["A", "B", "C", "D"].map((item) => (
          <span
            key={item}
            className="flex size-6 items-center justify-center border border-background bg-foreground/[0.08] font-mono text-[9px] text-foreground/45"
          >
            {item}
          </span>
        ))}
      </div>
    );
  }

  return (
    <div className="mt-3 font-mono text-[9px] leading-relaxed text-foreground/35">
      {kind === "stripe" ? "check() -> allow" : "route -> schema -> tests"}
    </div>
  );
}

export function HeroReadMe() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5, delay: 0.15, ease: "easeOut" }}
      className="flex w-full flex-col"
    >
      <div className="flex-1 overflow-x-hidden no-scrollbar">
        <div className="p-5 lg:px-8 lg:pt-20">
          <motion.article
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.4, delay: 0.3 }}
            className="no-scrollbar pb-0"
          >
            <h1 className="mb-4 flex items-center gap-3 font-mono text-sm text-neutral-900 dark:text-neutral-100 sm:mb-5 sm:text-[15px]">
              README
              <span className="h-px flex-1 bg-foreground/15" />
            </h1>

            <p className="mb-6 text-sm leading-relaxed text-foreground/80 dark:text-foreground/70 sm:mb-8 sm:text-[15px]">
              Authentication that lives{" "}
              <span className="font-medium text-foreground/90 dark:text-foreground/80">
                inside your Python app
              </span>
              . Composable, plugin-based, database-backed, and built for SaaS
              teams that need sessions, organizations, API keys, admin
              controls, and a real demo.
            </p>

            <InstallBlock />

            <div className="my-4 flex items-center gap-3">
              <div className="flex-1 border-t border-foreground/6" />
              <span className="shrink-0 font-mono text-[11px] uppercase tracking-wider text-foreground/50 dark:text-foreground/50 sm:text-xs">
                Built With
              </span>
              <div className="flex-1 border-t border-foreground/6" />
            </div>

            <TrustedBy />

            <div className="my-4 flex items-center gap-4">
              <span className="shrink-0 text-lg font-medium tracking-tight text-foreground/90 dark:text-foreground/80">
                Features
              </span>
              <div className="flex-1 border-t border-foreground/10" />
            </div>

            <div className="relative mb-2 grid grid-cols-1 overflow-hidden border border-foreground/[0.08] sm:grid-cols-2 md:grid-cols-3">
              {features.map((feature, index) => (
                <Link key={feature.label} href={feature.href} className="contents">
                  <motion.div
                    whileHover={{
                      y: -2,
                      transition: { duration: 0.2, ease: "easeOut" },
                    }}
                    className={cn(
                      "group/card relative min-h-[118px] border-foreground/[0.08] p-4 transition-all duration-200 hover:z-10 hover:bg-foreground/[0.02] hover:shadow-[inset_0_1px_0_0_rgba(128,128,128,0.1)] lg:p-5",
                      index < 8 && "border-b",
                      index >= 6 && "md:border-b-0",
                      index % 2 === 0 && index < 8 && "sm:border-r",
                      index % 3 === 2 && "md:border-r-0",
                      index % 2 !== 0 && index % 3 !== 2 && "md:border-r",
                    )}
                  >
                    <span className="absolute right-3 top-3 -translate-y-0.5 opacity-0 transition-all duration-200 group-hover/card:translate-y-0 group-hover/card:opacity-100 lg:right-4 lg:top-4">
                      <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="size-4 text-foreground/40 dark:text-foreground/50"
                        aria-hidden="true"
                      >
                        <line x1="7" y1="17" x2="17" y2="7" />
                        <polyline points="7 7 17 7 17 17" />
                      </svg>
                    </span>
                    <div className="mb-1">
                      <div className="font-mono text-[11px] tracking-wider text-foreground/45 transition-colors duration-200 group-hover/card:text-foreground/60 dark:text-foreground/30 dark:group-hover/card:text-foreground/40">
                        {String(index + 1).padStart(2, "0")}
                      </div>
                      <div className="text-[13px] font-medium text-foreground/80 transition-colors duration-200 dark:text-neutral-100">
                        {feature.headline}
                      </div>
                    </div>
                    <div className="text-[13px] leading-relaxed text-neutral-500 transition-colors duration-200 group-hover/card:text-neutral-400 dark:text-neutral-400 dark:group-hover/card:text-neutral-300">
                      {feature.desc}
                    </div>
                    <FeatureVisual kind={feature.kind} />
                  </motion.div>
                </Link>
              ))}
            </div>

            <div className="relative mt-10 overflow-hidden pb-16 pt-8">
              <div
                className="pointer-events-none absolute inset-0 select-none"
                aria-hidden="true"
                style={{
                  backgroundImage:
                    "radial-gradient(circle, currentColor 0.5px, transparent 0.5px)",
                  backgroundSize: "24px 24px",
                  opacity: 0.03,
                }}
              />
              <div className="relative space-y-6">
                <p className="text-balance text-center text-lg tracking-tight text-foreground/60 dark:text-foreground/50">
                  Run Python auth with a documented SaaS reference app.
                </p>
                <div className="flex flex-wrap items-center justify-center gap-4 pt-1">
                  <Link
                    href="/docs/introduction"
                    className="inline-flex items-center gap-1.5 bg-neutral-900 px-4 py-2 text-xs font-medium text-neutral-100 transition-colors hover:opacity-90 dark:bg-neutral-100 dark:text-neutral-900 sm:px-5 sm:text-sm"
                  >
                    Docs
                  </Link>
                  <Link
                    href="/docs/examples/fastapi-saas-demo"
                    className="group relative inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-neutral-600 transition-colors dark:text-neutral-300 sm:px-5 sm:text-sm"
                  >
                    <span
                      className="absolute inset-0 opacity-[0.04] transition-opacity group-hover:opacity-[0.08]"
                      style={{
                        backgroundImage:
                          "repeating-linear-gradient(-45deg, transparent, transparent 4px, currentColor 4px, currentColor 5px)",
                      }}
                    />
                    <span className="absolute -left-[6px] -right-[6px] top-0 h-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
                    <span className="absolute -left-[6px] -right-[6px] bottom-0 h-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
                    <span className="absolute -bottom-[6px] -top-[6px] left-0 w-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
                    <span className="absolute -bottom-[6px] -top-[6px] right-0 w-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
                    <span className="relative">Demo</span>
                  </Link>
                </div>
              </div>
            </div>
          </motion.article>
        </div>
      </div>
    </motion.div>
  );
}
