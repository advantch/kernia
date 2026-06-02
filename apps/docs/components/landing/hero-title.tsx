"use client";

import { motion } from "framer-motion";
import Link from "next/link";

export function HeroTitle() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="pointer-events-none relative z-[2] flex h-full w-full flex-col justify-center py-16"
    >
      <div>
        <Link
          href="/docs/examples/fastapi-saas-demo"
          className="group/badge pointer-events-auto relative inline-flex items-center gap-1.5 rounded-full bg-neutral-200/80 px-2.5 py-1 transition-colors hover:bg-neutral-200/70 dark:bg-neutral-800/80 dark:hover:bg-neutral-700/50"
        >
          <span className="text-xs font-light text-neutral-600 dark:text-neutral-100 sm:text-sm">
            SaaS reference app <span className="font-normal">| FastAPI and Vite</span>
          </span>
          <span className="text-neutral-500 transition-transform group-hover/badge:translate-x-0.5 dark:text-neutral-400">-&gt;</span>
        </Link>
        <h1 className="text-balance pt-3 text-2xl leading-tight tracking-tight text-neutral-800 dark:text-neutral-200 sm:pt-4 md:text-3xl xl:text-4xl">
          Python authentication for modern SaaS applications
        </h1>
        <p className="mt-4 max-w-xl text-sm leading-7 text-neutral-600 dark:text-neutral-400">
          Kernia brings authentication, users, sessions, organizations, plugins, admin configuration, and a tested SaaS demo to Python apps.
        </p>
        <div className="pointer-events-auto flex flex-wrap items-center gap-2 pt-4 sm:gap-3 sm:pt-5">
          <Link href="/docs/introduction" className="inline-flex items-center gap-1.5 bg-neutral-900 px-4 py-2 text-xs font-medium text-neutral-100 transition-colors hover:opacity-90 dark:bg-neutral-100 dark:text-neutral-900 sm:px-5 sm:text-sm">
            Docs
          </Link>
          <Link href="/docs/examples/fastapi-saas-demo" className="group relative inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-neutral-600 transition-colors dark:text-neutral-300 sm:px-5 sm:text-sm">
            <span className="absolute inset-0 opacity-[0.04] transition-opacity group-hover:opacity-[0.08]" style={{ backgroundImage: "repeating-linear-gradient(-45deg, transparent, transparent 4px, currentColor 4px, currentColor 5px)" }} />
            <span className="absolute -left-[6px] -right-[6px] top-0 h-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
            <span className="absolute -left-[6px] -right-[6px] bottom-0 h-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
            <span className="absolute -bottom-[6px] -top-[6px] left-0 w-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
            <span className="absolute -bottom-[6px] -top-[6px] right-0 w-px bg-foreground/20 transition-colors group-hover:bg-foreground/30" />
            <span className="relative">Demo</span>
          </Link>
        </div>
      </div>
    </motion.div>
  );
}
