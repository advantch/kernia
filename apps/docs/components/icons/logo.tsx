import type { SVGProps } from "react";
import { cn } from "@/lib/utils";

export function KerniaMark({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 64 64" aria-hidden="true" className={cn("size-8", className)} {...props}>
      <rect width="64" height="64" rx="9" fill="currentColor" opacity="0.08" />
      <path d="M17 14h10v16l16-16h12L36 33l20 17H43L27 36v14H17V14Z" fill="currentColor" />
      <path d="M29 30h12v8H29z" fill="var(--background)" opacity="0.88" />
    </svg>
  );
}

export function KerniaWordmark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2 font-medium tracking-tight", className)}>
      <KerniaMark className="size-6" />
      <span>Kernia</span>
    </span>
  );
}
