import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import { Icons } from "@/components/icons";
import { KerniaWordmark } from "@/components/icons/logo";

export const appName = "Kernia";
export const docsRoute = "/docs";
export const docsImageRoute = "/og/docs";
export const docsContentRoute = "/llms.mdx/docs";

export const gitConfig = {
  user: "advantch",
  repo: "kernia",
  branch: "feat/kernia-rebrand-parity",
};

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: <KerniaWordmark className="h-6" />,
      transparentMode: "top",
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      { text: "Docs", url: "/docs", active: "nested-url" },
      { text: "Demo", url: "/docs/examples/fastapi-saas-demo" },
      {
        text: "GitHub",
        url: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
        icon: <Icons.gitHub className="size-4" />,
        external: true,
      },
    ],
  };
}
