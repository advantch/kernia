import { Braces, Calendar, Hash, KeyRound, Link2, ToggleRight, Type } from "lucide-react";
import { cn } from "@/lib/utils";

type Field = {
  name: string;
  type: string;
  description?: string;
  isPrimaryKey?: boolean;
  isForeignKey?: boolean;
  isOptional?: boolean;
  isUnique?: boolean;
  references?: {
    model: string;
    field: string;
  };
};

function TypeIcon({ type }: { type: string }) {
  const normalized = type.toLowerCase();
  const className = "size-3.5 shrink-0 text-muted-foreground";

  if (normalized.includes("string") || normalized.includes("text")) {
    return <Type className={className} />;
  }
  if (normalized.includes("number") || normalized.includes("int")) {
    return <Hash className={className} />;
  }
  if (normalized.includes("bool")) {
    return <ToggleRight className={className} />;
  }
  if (normalized.includes("date") || normalized.includes("time")) {
    return <Calendar className={className} />;
  }
  return <Braces className={className} />;
}

export function DatabaseTable({
  fields,
  title,
}: {
  fields: Field[];
  title?: string;
}) {
  return (
    <div className="my-5 overflow-hidden rounded-lg border border-border">
      {title ? (
        <div className="border-b border-border bg-muted/30 px-4 py-3 text-sm font-medium">
          {title}
        </div>
      ) : null}
      <div className="divide-y divide-border">
        {fields.map((field) => (
          <div className="grid gap-3 px-4 py-3 md:grid-cols-[minmax(160px,220px)_1fr]" key={field.name}>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <code className="font-mono text-sm">{field.name}</code>
                {field.isPrimaryKey ? <KeyRound className="size-3.5 text-muted-foreground" /> : null}
                {field.isForeignKey ? <Link2 className="size-3.5 text-muted-foreground" /> : null}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <TypeIcon type={field.type} />
                <span>{field.type}</span>
                {field.isOptional ? <span>optional</span> : <span>required</span>}
                {field.isUnique ? <span>unique</span> : null}
              </div>
            </div>
            <div className="text-sm leading-6 text-muted-foreground">
              {field.description ?? "No description provided."}
              {field.references ? (
                <span className="block font-mono text-xs">
                  references {field.references.model}.{field.references.field}
                </span>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
