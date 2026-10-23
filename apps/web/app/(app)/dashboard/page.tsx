"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Card, Empty, SectionTitle, Spinner, severityColor } from "@/components/ui";

function Spark({ data }: { data: { date: string; count: number }[] }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  return (
    <div className="flex h-16 items-end gap-1">
      {data.map((d) => (
        <div
          key={d.date}
          title={`${d.date}: ${d.count}`}
          className="min-w-2 flex-1 rounded-sm bg-blue-500/40"
          style={{ height: `${Math.round((d.count / max) * 100)}%` }}
        />
      ))}
    </div>
  );
}

export default function DashboardPage() {
  const { data: m, isLoading } = useQuery({
    queryKey: ["metrics"],
    queryFn: () => api.metrics(),
    refetchInterval: 30_000,
  });

  if (isLoading || !m) return <Spinner />;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card>
          <div className="text-xs text-slate-400">Assets</div>
          <div className="mt-1 text-2xl font-bold text-white">{m.assets}</div>
        </Card>
        <Card>
          <div className="text-xs text-slate-400">Open findings</div>
          <div className="mt-1 text-2xl font-bold text-white">{m.open_findings}</div>
        </Card>
        <Card>
          <div className="text-xs text-slate-400">Resolved</div>
          <div className="mt-1 text-2xl font-bold text-white">{m.resolved_findings}</div>
        </Card>
        <Card>
          <div className="text-xs text-slate-400">Critical open</div>
          <div className="mt-1 text-2xl font-bold text-red-300">{m.severity.CRITICAL}</div>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <SectionTitle>Scans (14 days)</SectionTitle>
          <Spark data={m.scan_trend} />
        </Card>
        <Card>
          <SectionTitle>New findings (14 days)</SectionTitle>
          <Spark data={m.findings_trend} />
        </Card>
      </div>

      <Card>
        <SectionTitle>Recent findings</SectionTitle>
        {m.recent_findings.length === 0 ? (
          <Empty>No findings yet. Add an asset and run your first scan.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {m.recent_findings.map((f) => (
              <Link
                key={f.id}
                href={`/findings/${f.id}`}
                className="flex items-center justify-between py-2.5 text-sm hover:opacity-80"
              >
                <span className="truncate">
                  <Badge color={severityColor(f.severity)}>{f.severity}</Badge>
                  <span className="ml-2 text-slate-200">{f.title}</span>
                  <span className="ml-2 text-xs text-slate-500">{f.asset_name}</span>
                </span>
                <Badge color={(f as { state?: string }).state === "PATCHED" ? "green" : "neutral"}>
                  {(f as { state?: string }).state ?? "OPEN"}
                </Badge>
              </Link>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <SectionTitle>Recent scans</SectionTitle>
        {m.recent_scans.length === 0 ? (
          <Empty>No scans yet.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {m.recent_scans.map((s) => (
              <div key={s.id} className="flex items-center justify-between py-2.5 text-sm">
                <span className="text-slate-300">{s.asset_name ?? s.asset_id}</span>
                <Badge color={s.status === "COMPLETED" ? "green" : s.status === "FAILED" ? "CRITICAL" : "neutral"}>
                  {s.status}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
