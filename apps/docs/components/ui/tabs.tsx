import { cn } from "@/lib/utils";

export function Tabs({
  className,
  children,
}: {
  className?: string;
  children?: React.ReactNode;
}) {
  return <div className={cn("my-5 grid gap-3", className)}>{children}</div>;
}

export function Tab({
  value,
  title,
  className,
  children,
}: {
  value?: string;
  title?: string;
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <section className={cn("rounded-lg border border-border bg-card p-4", className)}>
      {(title ?? value) ? (
        <div className="mb-3 font-mono text-xs font-medium text-muted-foreground">
          {title ?? value}
        </div>
      ) : null}
      {children}
    </section>
  );
}
