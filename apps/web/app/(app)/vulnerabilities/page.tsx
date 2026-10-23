"use client";

import Link from "next/link";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { BookLock, Database } from "lucide-react";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { Badge, Card, Empty, Skeleton, Spinner } from "@/components/ui";
import { PageHeader } from "@/components/page";
import { SeverityBadge } from "@/components/badges";

const ALL_RESOLVED =
  "RESOLVED_PATCHED,RESOLVED_FIXED,RESOLVED_WONT_FIX,RESOLVED_FALSE_POSITIVE";

function VulnerabilityList() {
  const params = useSearchParams();
  const vuln = params.get("vuln") ?? "";

  const { data, isLoading, isError } = useQuery({
    queryKey: ["vulnerabilities-seen", vuln],
    queryFn: () => api.findings({ status: `${ALL_RESOLVED},OPEN`, vuln: vuln || undefined }),
    refetchInterval: 60_000,
  });

  const rows = data?.findings ?? [];
  const byVuln = new Map<string, Finding[]>();
  for (const f of rows) {
    const list = byVuln.get(f.vulnerability_id) ?? [];
    list.push(f);
    byVuln.set(f.vulnerability_id, list);
  }
  const vulns = [...byVuln.entries()].sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <PageHeader
        title="Vulnerabilities"
        subtitle="Every vulnerability Sentinel has ever flagged on your assets — one card per knowledge-base entry, with its live detection state."
      />
      <Card className="mt-6">
        {isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2].map((i) => <Skeleton key={i} className="h-14 w-full" />)}
          </div>
        ) : isError ? (
          <Empty>Could not load vulnerability catalog.</Empty>
        ) : vulns.length === 0 ? (
          <Empty icon={<Database className="h-8 w-8" aria-hidden />}>
            Nothing flagged yet. Detections will appear here gathered by
            vulnerability ID once scans run.
          </Empty>
        ) : (
          <ul className="divide-y divide-line">
            {vulns.map(([vid, items]) => {
              const open = items.filter((i) => i.status.startsWith("OPEN")).length;
              return (
                <li key={vid} className="py-3.5">
                  <Link href={`/findings?vuln=${encodeURIComponent(vid)}`} className="group block">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={items[0].severity} />
                      <span className="font-mono text-xs text-ink-3">{vid}</span>
                      <Badge color={open > 0 ? "CRITICAL" : "green"}>
                        {open > 0 ? `${open} open` : "all resolved"}
                      </Badge>
                      <span className="ml-auto text-[10px] text-ink-3">
                        {items.length} detection{items.length === 1 ? "" : "s"}
                      </span>
                    </div>
                    <div className="mt-1 text-sm font-medium text-ink group-hover:text-accent">
                      {items[0].title}
                    </div>
                    <div className="mt-0.5 text-xs text-ink-3">
                      Version window: {items[0].detected_version ?? "?"} → {items[0].fixed_version ?? "n/a"}
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
      <p className="mt-3 flex items-start gap-2 text-[11px] text-ink-3">
        <BookLock className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
        Entries come from the offline vulnerability database bundled with the
        scanner in this container — no cloud lookup occurs and no data leaves
        this machine.
      </p>
    </div>
  );
}

export default function VulnerabilitiesPage() {
  return (
    <Suspense fallback={<div className="p-6"><Spinner /></div>}>
      <VulnerabilityList />
    </Suspense>
  );
}
