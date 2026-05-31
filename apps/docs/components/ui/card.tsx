import { cn } from "@/lib/utils";

export function Card({ className, children }: { className?: string; children?: React.ReactNode }) {
  return <div className={cn("border border-border bg-card p-3", className)}>{children}</div>;
}
