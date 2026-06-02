import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const methodClassName: Record<string, string> = {
  GET: "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  POST: "border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300",
  PUT: "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  PATCH: "border-purple-500/25 bg-purple-500/10 text-purple-700 dark:text-purple-300",
  DELETE: "border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300",
};

export function APIMethod({
  children,
  path,
  method = "GET",
  className,
}: {
  children?: ReactNode;
  path?: string;
  method?: string;
  className?: string;
}) {
  const normalizedMethod = method.toUpperCase();

  return (
    <section className={cn("my-5 overflow-hidden rounded-lg border border-border bg-card", className)}>
      {path ? (
        <div className="flex items-center gap-2 border-b border-border bg-muted/30 px-4 py-3">
          <span
            className={cn(
              "rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold",
              methodClassName[normalizedMethod] ?? "border-border bg-muted text-muted-foreground",
            )}
          >
            {normalizedMethod}
          </span>
          <code className="break-all font-mono text-sm text-foreground">{path}</code>
        </div>
      ) : null}
      <div className="px-4 py-3 text-sm leading-6 [&>p:first-child]:mt-0 [&>p:last-child]:mb-0">
        {children}
      </div>
    </section>
  );
}

export function Endpoint(props: Parameters<typeof APIMethod>[0]) {
  return <APIMethod {...props} />;
}
