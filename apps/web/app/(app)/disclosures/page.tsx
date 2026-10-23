"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Card, Empty, Spinner } from "@/components/ui";

const statusColor = (s: string) =>
  s === "DELIVERED" || s === "SENT"
    ? "green"
    : s === "FAILED"
      ? "CRITICAL"
      : s === "DRAFT"
        ? "MEDIUM"
        : "neutral";

export default function DisclosuresPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["disclosures"],
    queryFn: () => api.disclosures(),
    refetchInterval: 20_000,
  });

  return (
    <div className="space-y-6">
      <Card>
        <h1 className="mb-3 text-lg font-semibold text-white">
          Responsible disclosures
        </h1>
        <p className="mb-3 text-xs text-slate-500">
          Draft → edit → test email → mark pending → approve → send. Nothing is
          sent without your explicit approval; recipients come only from
          contacts discovered on the asset itself.
        </p>
        {isLoading || !data ? (
          <Spinner />
        ) : data.disclosures.length === 0 ? (
          <Empty>
            Nothing here yet. Open a finding and choose &ldquo;Prepare
            disclosure&rdquo; to start the flow.
          </Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {data.disclosures.map((d) => (
              <Link
                key={d.id}
                href={`/disclosures/${d.id}`}
                className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm hover:opacity-80"
              >
                <div className="min-w-0">
                  <div className="truncate text-slate-200">{d.subject}</div>
                  <div className="truncate text-xs text-slate-600">
                    {d.asset_name} · {d.finding_title} → {d.recipient_email ?? "?"}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-600">
                    {new Date(d.created_at).toLocaleDateString()}
                  </span>
                  <Badge color={statusColor(d.status)}>{d.status}</Badge>
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
