"use client";

import Link from "next/link";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { FilterX, ShieldAlert, SlidersHorizontal } from "lucide-react";
import { api } from "@/lib/api";
import { Badge, Button, Card, Empty, Select, Skeleton, Spinner } from "@/components/ui";
import { PageHeader } from "@/components/page";
import { FindingStatusBadge, SeverityBadge } from "@/components/badges";
import { SEVERITY_ORDER, findingStatusLabelFor, formatDateTime } from "@/lib/format";

const OPEN_STATUS = "OPEN,OPEN_RISK_ACCEPTED,OPEN_TRACKED";
const RESOLVED_STATUS = "RESOLVED_PATCHED,RESOLVED_FIXED,RESOLVED_WONT_FIX,RESOLVED_FALSE_POSITIVE";

const STATUS_OPTIONS = [
  { v: OPEN_STATUS, label: "All open" },
  { v: "OPEN", label: "Open" },
  { v: "OPEN_RISK_ACCEPTED", label: "Open (risk accepted)" },
  { v: "OPEN_TRACKED", label: "Open (tracked upstream)" },
  { v: "RESOLVED_PATCHED", label: "Resolved (patched)" },
  { v: "RESOLVED_FIXED", label: "Resolved (fixed)" },
  { v: "RESOLVED_WONT_FIX", label: "Resolved (won't fix)" },
  { v: "RESOLVED_FALSE_POSITIVE", label: "False positive" },
  { v: `${OPEN_STATUS},${RESOLVED_STATUS}`, label: "All statuses" },
];

const CONFIDENCE_OPTIONS = ["", "HIGH" , "MEDIUM", "LOW" ];

function FindingsTable() {
  const params = useSearchParams();
  const severity = params.get("severity") ?? "";
  const status = params.get("status") ?? OPEN_STATUS;
  const confidence = params.get("confidence") ?? "";
  const assetId = params.get("asset_id") ?? "";
  const vuln = params.get("vuln") ?? "";

  const assets = useQuery({ queryKey: ["assets", "for-filter"], queryFn: () => api.assets() });
  const { data, isLoading, isError } = useQuery({
    queryKey: ["findings", { severity, status, confidence, assetId, vuln }],
    queryFn: () =>
      api.findings({
        severity: severity || undefined,
        status: status || undefined,
        asset_id: assetId || undefined,
        vuln: vuln || undefined,
      }),
    refetchInterval: 30_000,
  });

  function setParam(name: string, value: string) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(name, value);
    else next.delete(name);
    next.delete("page");
    window.history.replaceState(null, "", `/findings${next.toString() ? `?${next}` : ""}`);
  }

  const findings = data?.findings ?? [];
  const hasFilters = severity || assetId || vuln || confidence;
  const activeStatus = STATUS_OPTIONS.some((o) => o.v === status)
    ? status
    : STATUS_OPTIONS[0].v;

  return (
    <div className="mx-auto max-w-[1400px] p-6">
      <PageHeader
        title="Findings"
        subtitle="Everything the scanner observed — verification states are explicit, never implied."
      />

      {/* Filter bar (URL is the source of truth) */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-600">
          <SlidersHorizontal className="h-3 w-3" aria-hidden /> Filters
        </span>
        <Select
          aria-label="Filter by severity"
          className="w-40"
          value={severity}
          onChange={(e) => setParam("severity", e.target.value)}
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>{s === "CRITICAL" ? "Critical" : s === "HIGH" ? "High" : s === "MEDIUM" ? "Medium" : "Low"}</option>
          ))}
        </Select>
        <Select
          aria-label="Filter by status"
          className="w-48"
          value={activeStatus}
          onChange={(e) => setParam("status", e.target.value)}
        >
          {STATUS_OPTIONS.map((o) => (
            <option key={o.v} value={o.v}>{o.label}</option>
          ))}
        </Select>
        <Select
          aria-label="Filter by confidence"
          className="w-40"
          value={confidence}
          onChange={(e) => setParam("confidence", e.target.value)}
        >
          <option value="">All confidence</option>
          {CONFIDENCE_OPTIONS.filter(Boolean).map((c) => (
            <option key={c} value={c}>{c[0] + c.slice(1).toLowerCase()}</option>
          ))}
        </Select>
        <Select
          aria-label="Filter by asset"
          className="w-48"
          value={assetId}
          onChange={(e) => setParam("asset_id", e.target.value)}
        >
          <option value="">All assets</option>
          {(assets.data?.assets ?? []).map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </Select>
        {hasFilters ? (
          <Button size="sm" variant="ghost" onClick={() => window.history.replaceState(null, "", "/findings")}>
            <FilterX className="h-3.5 w-3.5" aria-hidden /> Clear
          </Button>
        ) : null}
      </div>

      <Card className="mt-4 overflow-x-auto">
        {isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        ) : isError ? (
          <Empty>Could not load findings. Is the API running?</Empty>
        ) : findings.length === 0 ? (
          <Empty icon={<ShieldAlert className="h-8 w-8" aria-hidden />}>
            No findings match the current filters.
          </Empty>
        ) : (
          <table className="w-full min-w-[860px]">
            <thead>
              <tr className="border-b border-[rgba(255,255,255,0.07)]">
                <th className="th">Severity</th>
                <th className="th">Vulnerability</th>
                <th className="th">Asset</th>
                <th className="th">Status</th>
                <th className="th text-right">Confidence</th>
                <th className="th text-right">CVSS</th>
                <th className="th text-right">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  className="border-b border-[rgba(255,255,255,0.04)] transition-colors last:border-0 hover:bg-[rgba(255,255,255,0.015)]"
                >
                  <td className="td"><SeverityBadge severity={f.severity} /></td>
                  <td className="td max-w-[340px]">
                    <Link href={`/findings/${f.id}`} className="font-medium text-slate-200 hover:text-blue-300">
                      {f.title}
                    </Link>
                    <div className="truncate text-[11px] text-slate-600">{f.vulnerability_id}</div>
                  </td>
                  <td className="td">
                    <Link href={`/assets/${f.asset_id}`} className="hover:text-slate-200">
                      {f.asset_name}
                    </Link>
                  </td>
                  <td className="td"><FindingStatusBadge status={f.status} /></td>
                  <td className="td text-right">{f.confidence}</td>
                  <td className="td text-right tabular-nums">{f.cvss ?? "—"}</td>
                  <td className="td text-right text-slate-500">{formatDateTime(f.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <p className="mt-3 text-[11px] text-slate-600">
        {isLoading ? <Spinner label="Loading…" /> : `${findings.length} finding${findings.length === 1 ? "" : "s"} shown · states reflect what the scanner could verify, not assumptions.`}
      </p>
    </div>
  );
}

export default function FindingsPage() {
  return (
    <Suspense fallback={<div className="p-6"><Spinner /></div>}>
      <FindingsTable />
    </Suspense>
  );
}
