"use client";

import { useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { api } from "@/lib/api";
import { Badge, Card, Empty, Skeleton } from "@/components/ui";
import { PageHeader } from "@/components/page";
import { formatDateTime } from "@/lib/format";

const actionColor: Record<string, "neutral" | "green" | "amber" | "CRITICAL" | "info"> = {
  SCAN_QUEUED: "info",
  SCAN_COMPLETED: "green",
  SCAN_FAILED: "CRITICAL",
  SCAN_STALE_FAILED: "CRITICAL",
  SCAN_STUCK: "CRITICAL",
  ASSET_CREATED: "neutral",
  ASSET_DELETED: "amber",
  DISCLOSURE_SENT: "green",
  DISCLOSURE_CANCELLED: "amber",
};

export default function AuditPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit"],
    queryFn: () => api.audit(),
    refetchInterval: 120_000,
  });

  const rows = data?.audit_logs ?? [];

  return (
    <div className="mx-auto max-w-[1000px] p-6">
      <PageHeader
        title="Audit log"
        subtitle="Every meaningful security action on this machine, newest first — kept locally for your records."
      />
      <Card className="mt-6 overflow-x-auto">
        {isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-9 w-full" />)}
          </div>
        ) : isError ? (
          <Empty>Could not load the audit log.</Empty>
        ) : rows.length === 0 ? (
          <Empty icon={<ScrollText className="h-8 w-8" aria-hidden />}>
            Nothing logged yet.
          </Empty>
        ) : (
          <table className="w-full min-w-[640px]">
            <thead>
              <tr className="border-b border-[rgba(255,255,255,0.07)]">
                <th className="th">When</th>
                <th className="th">Action</th>
                <th className="th">Resource</th>
                <th className="th">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((l) => (
                <tr
                  key={l.id}
                  className="border-b border-[rgba(255,255,255,0.04)] align-top transition-colors last:border-0 hover:bg-[rgba(255,255,255,0.015)]"
                >
                  <td className="td whitespace-nowrap text-slate-500">{formatDateTime(l.created_at)}</td>
                  <td className="td">
                    <Badge color={actionColor[l.action] ?? "neutral"}>{l.action}</Badge>
                  </td>
                  <td className="td font-mono text-[11px]">
                    {l.resource_type}
                    {l.asset_id ? <span className="block text-slate-600">asset {l.asset_id.slice(0, 8)}…</span> : null}
                  </td>
                  <td className="td font-mono text-[11px] text-slate-600">
                    {l.detail
                      ? Object.entries(l.detail)
                          .slice(0, 3)
                          .map(([k, v]) => `${k}: ${String(v).slice(0, 40)}`)
                          .join(" · ")
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
