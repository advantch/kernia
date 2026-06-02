import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const root = process.cwd();
const docsRoot = join(root, "content", "docs");
const repoRoot = join(root, "..", "..");

const forbidden = [
  "is part of Kernia's",
  "without relying on hidden JavaScript server code",
  "If this capability is packaged separately",
  "# Add the ",
  "## Topics\n",
  "## Topics covered",
  "## Python implementation notes",
  "Kernia can be easily integrated with",
  "Use the memory adapter when your application stores Kernia tables in that backend.",
  "Use the sqlalchemy adapter when your application stores Kernia tables in that backend.",
  "Use the redis storage adapter when your application stores Kernia tables in that backend.",
  "Registered by the",
  "Executes the ",
  "Processes the ",
  "Returns openapi.json data for the plugin.",
  "This plugin does not add its own table. It uses core tables, package tables documented on the related page, or request-time hooks.",
  "Test this plugin through the mounted FastAPI, Starlette, or Django route surface.",
  "BetterAuthOptions",
  "from better_auth",
  "better_auth",
  "better-auth ",
  "better-auth-",
  "mount_auth",
];

const files = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (entry.name.endsWith(".mdx") || entry.name.endsWith(".tsx")) files.push(path);
  }
}

walk(docsRoot);
walk(join(root, "components"));
walk(join(root, "app"));

const failures = [];

for (const file of files) {
  const text = readFileSync(file, "utf8");
  for (const pattern of forbidden) {
    if (text.includes(pattern)) {
      failures.push(`${relative(root, file)} contains forbidden pattern: ${pattern}`);
    }
  }
  if (/\bMETHOD_DISABLED\b/.test(text)) {
    failures.push(`${relative(root, file)} contains stale disabled-method error name: METHOD_DISABLED`);
  }
}

const requiredDocs = [
  "introduction.mdx",
  "installation.mdx",
  "basic-usage.mdx",
  "integrations/fastapi.mdx",
  "integrations/starlette.mdx",
  "integrations/django.mdx",
  "authentication/google.mdx",
  "authentication/apple.mdx",
  "plugins/admin.mdx",
  "plugins/organization.mdx",
  "plugins/admin-config.mdx",
  "plugins/mcp.mdx",
  "plugins/captcha.mdx",
  "plugins/device-authorization.mdx",
  "plugins/api-key/index.mdx",
  "plugins/stripe.mdx",
  "examples/fastapi-saas-demo.mdx",
];

for (const file of requiredDocs) {
  if (!existsSync(join(docsRoot, file))) {
    failures.push(`missing required doc: ${file}`);
  }
}

const parityFile = join(root, "docs-parity.md");
if (existsSync(parityFile)) {
  failures.push("apps/docs/docs-parity.md must not exist");
}

const mdxCount = files.filter((file) => file.startsWith(docsRoot) && file.endsWith(".mdx")).length;
if (mdxCount < 100) {
  failures.push(`docs tree is too small: expected at least 100 mdx pages, found ${mdxCount}`);
}

function docsHrefExists(href) {
  const [withoutQuery] = href.split("?");
  const slug = withoutQuery.split("#")[0].replace(/^\/docs\/?/, "");
  if (slug === "") return true;
  return (
    existsSync(join(docsRoot, `${slug}.mdx`)) ||
    existsSync(join(docsRoot, slug, "index.mdx"))
  );
}

for (const file of files) {
  const text = readFileSync(file, "utf8");
  const hrefs = [
    ...text.matchAll(/href=["'](\/docs(?:\/[^"']*)?)["']/g),
    ...text.matchAll(/\]\((\/docs(?:\/[^)#?]+)?(?:#[^)]+)?(?:\?[^)]*)?)\)/g),
  ].map((match) => match[1]);
  for (const href of hrefs) {
    if (!docsHrefExists(href)) {
      failures.push(`${relative(root, file)} links to missing docs page: ${href}`);
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\\n"));
  process.exit(1);
}

console.log(`docs quality passed (${mdxCount} MDX pages checked)`);
