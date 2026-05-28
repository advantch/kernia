import type { Metadata } from "next";

export const baseUrl =
  process.env.NODE_ENV === "development" ||
  (!process.env.VERCEL_PROJECT_PRODUCTION_URL && !process.env.VERCEL_URL)
    ? new URL("http://localhost:3000")
    : new URL(
        `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL}`,
      );

export function createMetadata(override: Metadata): Metadata {
  return {
    ...override,
    metadataBase: baseUrl,
    openGraph: {
      title: override.title ?? undefined,
      description: override.description ?? undefined,
      url: baseUrl.toString(),
      images: "/og.png",
      siteName: "Kernia",
      ...override.openGraph,
    },
    twitter: {
      card: "summary_large_image",
      title: override.title ?? undefined,
      description: override.description ?? undefined,
      images: "/og.png",
      ...override.twitter,
    },
  };
}
