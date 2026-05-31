import { cn } from "@/lib/utils";

export function Accordion({ className, children }: { className?: string; children?: React.ReactNode }) {
  return <div className={cn("border border-border bg-card p-3", className)}>{children}</div>;
}
