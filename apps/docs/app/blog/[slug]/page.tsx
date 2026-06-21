import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { DocsBody } from "fumadocs-ui/layouts/docs/page";
import { getMDXComponents } from "@/components/docs/mdx-components";
import { blogSource, formatPostDate } from "@/lib/blog";

type PageProps = { params: Promise<{ slug: string }> };

export default async function BlogPostPage(props: PageProps) {
  const { slug } = await props.params;
  const page = blogSource.getPage([slug]);
  if (!page || page.data.draft) notFound();

  const { body: MDX } = await page.data.load();

  return (
    <article className="mx-auto w-full max-w-3xl px-5 pb-24 pt-12 sm:px-6">
      <header className="border-b border-foreground/[0.06] pb-8">
        <Link
          href="/blog"
          className="font-mono text-[12px] text-foreground/45 transition-colors hover:text-foreground"
        >
          ← blog
        </Link>
        <h1 className="mt-4 text-3xl font-semibold tracking-tight">
          {page.data.title}
        </h1>
        {page.data.description ? (
          <p className="mt-2 text-foreground/60">{page.data.description}</p>
        ) : null}
        <p className="mt-4 font-mono text-[12px] text-foreground/45">
          <time dateTime={new Date(page.data.date).toISOString()}>
            {formatPostDate(page.data.date)}
          </time>
          {" · "}
          {page.data.author}
        </p>
      </header>
      <DocsBody className="prose mt-8 max-w-none">
        <MDX components={getMDXComponents()} />
      </DocsBody>
    </article>
  );
}

export function generateStaticParams() {
  return blogSource
    .getPages()
    .filter((post) => !post.data.draft)
    .map((post) => ({ slug: post.slugs[0] }));
}

export async function generateMetadata(props: PageProps): Promise<Metadata> {
  const { slug } = await props.params;
  const page = blogSource.getPage([slug]);
  if (!page || page.data.draft) notFound();
  return {
    title: page.data.title,
    description: page.data.description,
  };
}
