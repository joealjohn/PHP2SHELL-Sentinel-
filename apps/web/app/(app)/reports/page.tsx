"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Card, Empty, Spinner, severityColor } from "@/components/ui";

export default function ReportsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.reports(),
  });

  return (
    <div className="space-y-6">
      <Card>
        <h1 className="mb-3 text-lg font-semibold text-white">Vulnerability reports</h1>
        <p className="mb-3 text-xs text-slate-500">
          Shareable, non-exploitative reports: machine-readable JSON for trackers
          and a human-readable HTML document. Evidence is redacted-safe and every
          report states that no exploitation was performed.
        </p>
        {isLoading || !data ? (
          <Spinner />
        ) : data.reports.length === 0 ? (
          <Empty>Reports appear here once findings exist.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {data.reports.map((r) => (
              <div
                key={r.finding_id}
                className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm"
              >
                <div className="min-w-0">
                  <div>
                    <Badge color={severityColor(r.severity)}>{r.severity}</Badge>
                    <span className="ml-2 text-slate-200">{r.title}</span>
                  </div>
                  <div className="text-xs text-slate-600">
                    {r.vulnerability_id} · {r.asset_name}
                  </div>
                </div>
                <div className="flex gap-2 text-xs">
                  {/* API returns /reports/... without /api prefix */}
                  <a className="text-blue-300 hover:underline" href={`/api${r.json_url}`}>
                    JSON
                  </a>
                  <a className="text-blue-300 hover:underline" href={`/api${r.html_url}`}>
                    HTML
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
