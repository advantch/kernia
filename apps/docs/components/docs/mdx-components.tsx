import defaultMdxComponents from "fumadocs-ui/mdx";
import type { MDXComponents } from "mdx/types";
import { APIMethod, Endpoint } from "./api-method";
import { DatabaseTable } from "./database-table";
import {
  Accordion,
  Accordions,
  Card,
  Cards,
  Features,
  File,
  Files,
  Folder,
  ForkButton,
  GenerateAppleJwt,
  GenerateSecret,
  MdxLink,
  Resource,
  TypeTable,
} from "./mdx-widgets";
import { ProviderHeading, ProviderIcon } from "./provider-icons";
import { Step, Steps } from "./steps";
import { Callout } from "../ui/callout";
import { Tab, Tabs } from "../ui/tabs";

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...defaultMdxComponents,
    APIMethod,
    Accordion,
    Accordions,
    Callout,
    Card,
    Cards,
    DatabaseTable,
    Endpoint,
    Features,
    File,
    Files,
    Folder,
    ForkButton,
    GenerateAppleJwt,
    GenerateSecret,
    Link: MdxLink,
    ProviderHeading,
    ProviderIcon,
    Resource,
    Step,
    Steps,
    Tab,
    Tabs,
    TypeTable,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
