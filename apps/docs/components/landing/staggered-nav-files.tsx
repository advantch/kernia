"use client";

import { Search } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { KerniaWordmark } from "@/components/icons/logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";

const navFiles = [
  { name: "readme", href: "/" },
  { name: "docs", href: "/docs" },
  { name: "demo", href: "/docs/examples/fastapi-saas-demo" },
  { name: "blog", href: "/blog" },
];

export function StaggeredNavFiles() {
  const pathname = usePathname();
  return (
    <header className="fixed inset-x-0 top-0 z-50 h-[var(--landing-topbar-height)] border-b border-foreground/[0.06] bg-background/90 backdrop-blur">
      <div className="flex h-full items-center">
        <Link href="/" className="flex h-full w-[22vw] max-w-[300px] items-center border-r border-foreground/[0.06] px-4">
          <KerniaWordmark />
        </Link>
        <nav className="flex h-full items-center">
          {navFiles.map((item) => (
            <Link key={item.href} href={item.href} className={cn("flex h-full items-center border-r border-foreground/[0.06] px-4 font-mono text-[12px] text-foreground/50 transition-colors hover:text-foreground", pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href)) ? "bg-foreground/[0.03] text-foreground" : "")}>{item.name}</Link>
          ))}
        </nav>
        <div className="ml-auto flex h-full items-center border-l border-foreground/[0.06]">
          <Link href="/docs" className="hidden h-full items-center gap-2 border-r border-foreground/[0.06] px-4 text-[12px] text-foreground/55 hover:text-foreground sm:flex"><Search className="size-3.5" /> Search</Link>
          <Link href="https://github.com/advantch/kernia" className="hidden h-full items-center border-r border-foreground/[0.06] px-4 font-mono text-[12px] text-foreground/55 hover:text-foreground md:flex">GitHub</Link>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
