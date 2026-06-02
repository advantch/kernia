"use client";

import type { ReactNode } from "react";

export type PageEntry = { name: string; url: string };

export function DocsProvider({ children }: { pages: PageEntry[]; children: ReactNode }) {
  return <>{children}</>;
}
