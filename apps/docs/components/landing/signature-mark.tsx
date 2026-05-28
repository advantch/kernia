import Link from "next/link";
import { Icons } from "@/components/icons";
import { ThemeToggle } from "@/components/theme-toggle";

export function SignatureMark() {
  return (
    <div className="flex select-none items-center justify-between gap-3 font-mono text-[11px] text-foreground/50">
      <div className="flex items-center gap-3">
        <Link href="/docs" className="transition-colors hover:text-foreground/80">Docs</Link>
        <span className="text-foreground/15">/</span>
        <Link href="/docs/examples/fastapi-saas-demo" className="transition-colors hover:text-foreground/80">Demo</Link>
      </div>
      <div className="flex items-center gap-3">
        <Link href="https://github.com/advantch/kernia" aria-label="GitHub" className="text-foreground/50 transition-colors hover:text-foreground/80">
          <Icons.gitHub className="size-3.5" />
        </Link>
        <div className="flex items-center"><span className="mr-1 h-3 w-px bg-foreground/15" /><div className="-mx-2"><ThemeToggle /></div></div>
      </div>
    </div>
  );
}
