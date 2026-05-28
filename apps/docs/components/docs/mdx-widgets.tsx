import Link from "next/link";
import type { AnchorHTMLAttributes, ReactNode } from "react";
import {
  ChevronDown,
  FileText,
  FolderClosed,
  GitFork,
  KeyRound,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";

export function GenerateSecret() {
  return (
    <div className="my-4 rounded-lg border border-border bg-muted/30 p-4 font-mono text-sm">
      KERNIA_SECRET=&lt;generate at least 32 random bytes&gt;
    </div>
  );
}

export function GenerateAppleJwt() {
  return (
    <div className="my-4 rounded-lg border border-border bg-muted/30 p-4 text-sm leading-6">
      Generate the Apple client secret with an ES256-signed JWT whose issuer is
      your Apple Team ID, subject is the Services ID, audience is
      <code>https://appleid.apple.com</code>, and expiration is no more than
      180 days.
    </div>
  );
}

export function Cards({
  children,
  className,
}: {
  children?: ReactNode;
  className?: string;
}) {
  return <div className={cn("my-5 grid gap-3 sm:grid-cols-2", className)}>{children}</div>;
}

export function Card({
  title,
  href,
  children,
}: {
  title?: ReactNode;
  href?: string;
  children?: ReactNode;
}) {
  const content = (
    <div className="rounded-lg border border-border bg-card p-4 text-sm leading-6 transition-colors hover:bg-muted/30">
      {title ? <div className="mb-1 font-medium text-foreground">{title}</div> : null}
      <div className="text-muted-foreground">{children}</div>
    </div>
  );
  return href ? <Link href={href}>{content}</Link> : content;
}

export function Accordions({ children }: { children?: ReactNode }) {
  return <div className="my-5 divide-y divide-border rounded-lg border border-border">{children}</div>;
}

export function Accordion({
  title,
  children,
}: {
  title?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <details className="group p-4">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-medium">
        {title}
        <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" />
      </summary>
      <div className="mt-3 text-sm leading-6 text-muted-foreground">{children}</div>
    </details>
  );
}

export function Files({ children }: { children?: ReactNode }) {
  return <div className="my-5 rounded-lg border border-border bg-card p-3">{children}</div>;
}

export function Folder({ name, children }: { name?: string; children?: ReactNode }) {
  return (
    <div className="my-2">
      {name ? (
        <div className="mb-2 flex items-center gap-2 font-mono text-xs text-muted-foreground">
          <FolderClosed className="size-3.5" />
          {name}
        </div>
      ) : null}
      <div className="ml-4 border-l border-border pl-3">{children}</div>
    </div>
  );
}

export function File({ name }: { name?: string }) {
  return (
    <div className="flex items-center gap-2 py-1 font-mono text-xs text-muted-foreground">
      <FileText className="size-3.5" />
      {name}
    </div>
  );
}

export function TypeTable({ children }: { children?: ReactNode }) {
  return <div className="my-5 overflow-x-auto rounded-lg border border-border p-4">{children}</div>;
}

export function Resource({ children }: { children?: ReactNode }) {
  return <div className="my-5 grid gap-3">{children}</div>;
}

export function ForkButton({ url }: { url: string }) {
  return (
    <a
      className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm"
      href={url}
      rel="noreferrer"
      target="_blank"
    >
      <GitFork className="size-4" />
      Fork
    </a>
  );
}

export function Features({ stars }: { stars?: string | null }) {
  return (
    <div className="my-5 grid gap-3 sm:grid-cols-3">
      {[
        ["Python server", "FastAPI, Starlette, and Django adapters."],
        ["Wire-compatible", "Use Better Auth-compatible client flows."],
        ["Plugin model", "Add organizations, API keys, SSO, and billing."],
      ].map(([title, body]) => (
        <div className="rounded-lg border border-border bg-card p-4" key={title}>
          <Sparkles className="mb-2 size-4 text-muted-foreground" />
          <div className="font-medium">{title}</div>
          <p className="mb-0 mt-1 text-sm text-muted-foreground">{body}</p>
        </div>
      ))}
      {stars ? (
        <div className="rounded-lg border border-border bg-card p-4">
          <KeyRound className="mb-2 size-4 text-muted-foreground" />
          <div className="font-medium">{stars}</div>
          <p className="mb-0 mt-1 text-sm text-muted-foreground">Project activity</p>
        </div>
      ) : null}
    </div>
  );
}

export function MdxLink({ href = "#", ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  if (href.startsWith("http")) {
    return <a href={href} {...props} rel="noreferrer" target="_blank" />;
  }
  return <Link href={href} {...props} />;
}
