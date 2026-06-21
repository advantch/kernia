import { blog } from "@/.source/server";
import { loader } from "fumadocs-core/source";

export const blogSource = loader({
  baseUrl: "/blog",
  source: blog.toFumadocsSource(),
});

export type BlogPost = (typeof blogSource)["$inferPage"];

export function getBlogPosts(): BlogPost[] {
  return blogSource
    .getPages()
    .filter((post) => !post.data.draft)
    .sort(
      (a, b) => new Date(b.data.date).getTime() - new Date(a.data.date).getTime(),
    );
}

// Async-mode frontmatter can arrive as an ISO string rather than a Date, so
// normalize before formatting.
export function formatPostDate(date: Date | string): string {
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}
