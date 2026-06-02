import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Steps({
  className,
  children,
}: {
  className?: string;
  children?: ReactNode;
}) {
  return (
    <div className={cn("my-6 grid gap-0 border-l border-border pl-6", className)}>
      {children}
    </div>
  );
}

export function Step({
  className,
  children,
}: {
  className?: string;
  children?: ReactNode;
}) {
  return (
    <section className={cn("relative pb-8 last:pb-0", className)}>
      <div className="absolute -left-[31px] top-1 size-3 rounded-full border border-border bg-background ring-4 ring-background" />
      {children}
    </section>
  );
}
