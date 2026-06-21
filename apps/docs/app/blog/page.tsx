import type { Metadata } from "next";
import Link from "next/link";
import { formatPostDate, getBlogPosts } from "@/lib/blog";
import { createMetadata } from "@/lib/metadata";

export const metadata: Metadata = createMetadata({
  title: "Blog",
  description:
    "Notes on building Kernia — Python authentication for modern SaaS apps.",
});

export default function BlogIndexPage() {
  const posts = getBlogPosts();

  return (
    <div className="mx-auto w-full max-w-3xl px-5 pb-24 pt-12 sm:px-6">
      <div className="border-b border-foreground/[0.06] pb-8">
        <p className="font-mono text-[12px] uppercase tracking-wider text-foreground/50">
          blog
        </p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">
          Building Kernia
        </h1>
        <p className="mt-2 text-foreground/60">
          Engineering notes, release write-ups, and what we learn shipping
          open-source auth for Python.
        </p>
      </div>
      {posts.length === 0 ? (
        <div className="py-16">
          <p className="font-mono text-[13px] text-foreground/50">
            First posts are on the way. Meanwhile, the{" "}
            <Link href="/docs" className="text-foreground underline underline-offset-4">
              docs
            </Link>{" "}
            and{" "}
            <a
              href="https://github.com/advantch/kernia"
              className="text-foreground underline underline-offset-4"
            >
              GitHub repo
            </a>{" "}
            are live.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-foreground/[0.06]">
          {posts.map((post) => (
            <li key={post.url}>
              <Link
                href={post.url}
                className="group flex flex-col gap-1 py-7 sm:flex-row sm:items-baseline sm:gap-6"
              >
                <time
                  dateTime={new Date(post.data.date).toISOString()}
                  className="shrink-0 font-mono text-[12px] text-foreground/45 sm:w-28"
                >
                  {formatPostDate(post.data.date)}
                </time>
                <div>
                  <h2 className="font-medium text-foreground transition-colors group-hover:text-foreground/70">
                    {post.data.title}
                  </h2>
                  {post.data.description ? (
                    <p className="mt-1 text-sm text-foreground/55">
                      {post.data.description}
                    </p>
                  ) : null}
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
