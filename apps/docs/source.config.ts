import { defineConfig, defineDocs } from "fumadocs-mdx/config";
import lastModified from "fumadocs-mdx/plugins/last-modified";
import {
  createFileSystemGeneratorCache,
  createGenerator,
  remarkAutoTypeTable,
} from "fumadocs-typescript";
import * as z from "zod";

export const docs = defineDocs({
  dir: "./content/docs",
  docs: {
    postprocess: {
      includeProcessedMarkdown: true,
    },
    async: true,
  },
  meta: {
    schema: z.object({
      title: z.string().optional(),
      pages: z.array(z.string()).optional(),
      root: z.boolean().optional(),
    }),
  },
});

const generator = createGenerator({
  cache: createFileSystemGeneratorCache(".next/fumadocs-typescript"),
});

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [[remarkAutoTypeTable, { generator }]],
  },
  plugins: [lastModified()],
});
