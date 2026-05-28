import { GeistPixelSquare } from "geist/font/pixel";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { StaggeredNavFiles } from "@/components/landing/staggered-nav-files";
import { Providers } from "@/components/providers";
import { createMetadata } from "@/lib/metadata";

const fontSans = Geist({ subsets: ["latin"], variable: "--font-sans" });
const fontMono = Geist_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = createMetadata({
  title: { template: "%s | Kernia", default: "Kernia" },
  description: "Python authentication for modern SaaS apps.",
});

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning data-scroll-behavior="smooth">
      <body className={`${fontSans.variable} ${fontMono.variable} ${GeistPixelSquare.variable} font-sans antialiased`} suppressHydrationWarning>
        <Providers>
          <div className="relative min-h-dvh">
            <StaggeredNavFiles />
            {children}
          </div>
        </Providers>
      </body>
    </html>
  );
}
