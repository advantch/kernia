import type { ReactNode } from "react";

export default function BlogLayout({ children }: { children: ReactNode }) {
  return (
    <main className="min-h-dvh pt-[var(--landing-topbar-height)]">
      {children}
    </main>
  );
}
