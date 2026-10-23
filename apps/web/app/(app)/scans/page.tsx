"use client";

import Link from "next/link";
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar, OctagonAlert, SlidersHorizontal } from "lucide-react";
import { ApiError, api } from "@/lib/api";
import { Badge, Button, Card, Empty, ErrorBanner, Select, Skeleton, Spinner, TimeAgo } from "@/components/ui";
import { PageHeader } from "@/components/page";
import { ScanStatusBadge } from "@/components/badges";
import { formatDateTime, formatDuration, friendlyScanError, scanStatusLabel } from "@/lib/format";

const STATUS_VALUES = ["", "COMPLETED", "FAILED", "QUEUED", "SCANNING", "ANALYZING"] as const;

function ScansTable() {
  const params = useSearchParams();
  const qc = useQueryClient();
  const [formError, setFormError] = useState<string | null>(null);
  const status = params.get("status") ?? "";
  const assetId = params.get("asset_id") ?? "";

  const assets = useQuery({ queryKey: ["assets", "scans-filter"], queryFn: () => api.assets() });
  const { data, isLoading, isError } = useQuery({
    queryKey: ["scans-list", { status, assetId }],
    queryFn: async () => {
      const all = await api.scans(assetId || undefined, 200);
      return status ? all.scans.filter((s) => s.status === status) : all.scans;
    },
    refetchInterval: 15_000,
  });

  function setParam(name: string, value: string) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(name, value);
    else next.delete(name);
    window.history.replaceState(null, "", `/scans${next.toString() ? `?${next}` : ""}`);
  }

  const cancel = useMutation({
    mutationFn: (id: string) => api.cancelScan(id),
    onMutate: () => setFormError(null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans-list"] }),
    onError: (e) =>
      setFormError(e instanceof ApiError ? e.message : "Failed to cancel scan."),
  });

  const rows = data ?? [];
  const names = new Map((assets.data?.assets ?? []).map((a) => [a.id, a.name]));

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <PageHeader
        title="Scans"
        subtitle="Every scan execution — queued, running, completed, or failed — with real durations and errors."
      />
      {formError ? <div className="mt-4"><ErrorBanner message={formError} /></div> : null}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-600">
          <SlidersHorizontal className="h-3 w-3" aria-hidden /> Filters
        </span>
        <Select
          aria-label="Filter scans by status"
          className="w-44"
          value={status}
          onChange={(e) => setParam("status", e.target.value)}
        >
          <option value="">All statuses</option>
          {STATUS_VALUES.filter(Boolean).map((s) => (
            <option key={s} value={s}>{scanStatusLabel[s]}</option>
          ))}
        </Select>
        <Select
          aria-label="Filter scans by asset"
          className="w-52"
          value={assetId}
          onChange={(e) => setParam("asset_id", e.target.value)}
        >
          <option value="">All assets</option>
          {(assets.data?.assets ?? []).map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </Select>
      </div>

      <Card className="mt-4 overflow-x-auto">
        {isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        ) : isError ? (
          <Empty>Could not load scans.</Empty>
        ) : rows.length === 0 ? (
          <Empty icon={<Radar className="h-8 w-8" aria-hidden />}>
            No scans yet.{" "}
            <Link href="/assets" className="text-blue-400 hover:underline">
              Start one from an asset
            </Link>
            .
          </Empty>
        ) : (
          <table className="w-full min-w-[720px]">
            <thead>
              <tr className="border-b border-[rgba(255,255,255,0.07)]">
                <th className="th">Started</th>
                <th className="th">Asset</th>
                <th className="th">Status</th>
                <th className="th text-right">Duration</th>
                <th className="th text-right">Result</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => {
                const running = ["QUEUED", "SCANNING", "ANALYZING"].includes(s.status);
                return (
                  <tr
                    key={s.id}
                    className="border-b border-[rgba(255,255,255,0.04)] transition-colors last:border-0 hover:bg-[rgba(255,255,255,0.015)]"
                  >
                    <td className="td">
                      <span className="text-slate-300">{formatDateTime(s.created_at)}</span>
                      <TimeAgo date={s.created_at} className="block text-[10px] text-slate-600" />
                    </td>
                    <td className="td">
                      <Link href={`/assets/${s.asset_id}`} className="hover:text-slate-200">
                        {s.asset_name ?? names.get(s.asset_id) ?? "unknown asset"}
                      </Link>
                    </td>
                    <td className="td"><ScanStatusBadge status={s.status} /></td>
                    <td className="td text-right tabular-nums">{formatDuration(s.duration_seconds)}</td>
                    <td className="td text-right">
                      {s.status === "FAILED" && s.error ? (
                        <Badge color="CRITICAL" className="max-w-[240px]">
                          <OctagonAlert className="h-3 w-3 shrink-0" aria-hidden />
                          <span className="truncate" title={friendlyScanError(s.error)}>{friendlyScanError(s.error)}</span>
                        </Badge>
                      ) : running ? (
                        <Button size="sm" variant="ghost" onClick={() => cancel.mutate(s.id)} disabled={cancel.isPending}>
                          Cancel
                        </Button>
                      ) : (
                        <span className="text-slate-600">
                          Summary: {s.summary ? String((s.summary as Record<string, unknown>).checks_passed ?? `${Object.keys(s.summary).length} fields`) : "—"}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
      <p className="mt-3 text-[11px] text-slate-600">
        {isLoading ? <Spinner label="Loading…" /> : `${rows.length} scan${rows.length === 1 ? "" : "s"} · stuck runs fail automatically after the sweeper threshold.`}
      </p>
    </div>
  );
}

export default function ScansPage() {
  return (
    <Suspense fallback={<div className="p-6"><Spinner /></div>}>
      <ScansTable />
    </Suspense>
  );
}
