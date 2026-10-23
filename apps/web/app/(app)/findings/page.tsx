"use client";

import Link from "next/link";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Badge, Card, Empty, Input, Spinner, severityColor } from "@/components/ui";

const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export default function FindingsPage() {
  const [severity, setSeverity] = useState<string>("");
  const { data, isLoading } = useQuery({
    queryKey: ["findings", severity],
    queryFn: () => api.findings({ severity: severity || undefined }),
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <Card>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h1 className="text-lg font-semibold text-white">Findings</h1>
          <select
            className="input max-w-40"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s || "All severities"}
              </option>
            ))}
          </select>
        </div>
        {isLoading || !data ? (
          <Spinner />
        ) : data.findings.length === 0 ? (
          <Empty>No findings{severity ? ` at ${severity}` : ""}.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {data.findings.map((f) => (
              <Link
                key={f.id}
                href={`/findings/${f.id}`}
                className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm hover:opacity-80"
              >
                <div className="min-w-0">
                  <div>
                    <Badge color={severityColor(f.severity)}>{f.severity}</Badge>
                    {(f as { state?: string }).state === "PATCHED" && (
                      <Badge color="green">PATCHED</Badge>
                    )}
                    <span className="ml-2 text-slate-200">{f.title}</span>
                  </div>
                  <div className="mt-0.5 truncate text-xs text-slate-600">
                    {f.vulnerability_id} · {f.asset_name}
                  </div>
                </div>
                <div className="text-right text-xs text-slate-500">
                  {f.cvss !== null && <span>CVSS {f.cvss} · </span>}
                  {new Date(f.last_seen).toLocaleDateString()}
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
