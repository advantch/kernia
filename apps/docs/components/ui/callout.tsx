import type { HTMLAttributes, ReactNode } from "react";
import { AlertCircle, CheckCircle2, Info, TriangleAlert } from "lucide-react";
import { cn } from "@/lib/utils";

type CalloutType = "info" | "warn" | "success" | "error";

const icons = {
  info: Info,
  warn: TriangleAlert,
  success: CheckCircle2,
  error: AlertCircle,
} satisfies Record<CalloutType, typeof Info>;

const styles = {
  info: "border-blue-500/20 bg-blue-500/[0.06] text-blue-950 dark:text-blue-100",
  warn: "border-amber-500/25 bg-amber-500/[0.08] text-amber-950 dark:text-amber-100",
  success: "border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-950 dark:text-emerald-100",
  error: "border-red-500/20 bg-red-500/[0.07] text-red-950 dark:text-red-100",
} satisfies Record<CalloutType, string>;

export function Callout({
  className,
  children,
  title,
  type = "info",
  ...props
}: HTMLAttributes<HTMLDivElement> & {
  children?: ReactNode;
  title?: ReactNode;
  type?: CalloutType;
}) {
  const Icon = icons[type];

  return (
    <div
      className={cn(
        "my-5 flex gap-3 rounded-lg border px-4 py-3 text-sm leading-6",
        styles[type],
        className,
      )}
      {...props}
    >
      <Icon className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0">
        {title ? <div className="mb-1 font-medium">{title}</div> : null}
        <div className="[&>p:first-child]:mt-0 [&>p:last-child]:mb-0">{children}</div>
      </div>
    </div>
  );
}
