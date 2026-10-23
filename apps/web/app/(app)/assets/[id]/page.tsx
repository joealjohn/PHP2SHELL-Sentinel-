"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api";
import { Badge, Button, Card, Empty, SectionTitle, Spinner } from "@/components/ui";

function statusColor(s: string) {
  if (s === "COMPLETED") return "green" as const;
  if (s === "FAILED") return "CRITICAL" as const;
  return "neutral" as const;
}

export default function AssetDetailPage() {
  const { id: assetId } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const asset = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => api.asset(assetId),
    refetchInterval: 15_000,
  });
  const scans = useQuery({
    queryKey: ["asset-scans", assetId],
    queryFn: () => api.assetScans(assetId),
    refetchInterval: 10_000,
  });
  const contacts = useQuery({
    queryKey: ["asset-contacts", assetId],
    queryFn: () => api.contacts(assetId),
  });

  const doScan = useMutation({
    mutationFn: () => api.queueScan(assetId),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["asset-scans", assetId] });
      qc.invalidateQueries({ queryKey: ["asset", assetId] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to queue scan."),
  });
  const discover = useMutation({
    mutationFn: () => api.discoverContacts(assetId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["asset-contacts", assetId] }),
  });
  const confirmAuth = useMutation({
    mutationFn: (v: boolean) =>
      api.updateAsset(assetId, { authorization_confirmed: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["asset", assetId] }),
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to update asset."),
  });

  if (asset.isLoading) return <Spinner />;
  if (asset.isError || !asset.data)
    return <Empty>Asset not found (or not yours).</Empty>;
  const a = asset.data;

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold text-white">{a.name}</h1>
            <p className="text-xs text-slate-500">{a.url}</p>
            {a.description && (
              <p className="mt-1 text-sm text-slate-400">{a.description}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            {a.authorization_confirmed ? (
              <Badge color="green">authorized</Badge>
            ) : (
              <Button
                variant="secondary"
                onClick={() => confirmAuth.mutate(true)}
                disabled={confirmAuth.isPending}
              >
                {confirmAuth.isPending ? "Confirming…" : "Confirm authorization"}
              </Button>
            )}
            {a.open_findings !== null && a.open_findings > 0 && (
              <Badge color="CRITICAL">{a.open_findings} open</Badge>
            )}
            <Button onClick={() => doScan.mutate()} disabled={doScan.isPending}>
              {doScan.isPending ? "Queuing…" : "Scan now"}
            </Button>
          </div>
        </div>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
        <div className="mt-3 grid grid-cols-2 text-xs text-slate-500 sm:grid-cols-4">
          <div>Monitoring: {a.monitoring_enabled ? "on" : "off"}</div>
          <div>Interval: {Math.round(a.scan_interval_seconds / 3600)}h</div>
          <div>
            Last scan:{" "}
            {a.last_scan_at ? new Date(a.last_scan_at).toLocaleString() : "never"}
          </div>
          <div>
            Next scan:{" "}
            {a.next_scan_at ? new Date(a.next_scan_at).toLocaleString() : "—"}
          </div>
        </div>
      </Card>

      <Card>
        <SectionTitle>Scans</SectionTitle>
        {scans.isLoading || !scans.data ? (
          <Spinner />
        ) : scans.data.scans.length === 0 ? (
          <Empty>No scans yet.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {scans.data.scans.map((s) => (
              <div
                key={s.id}
                className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm"
              >
                <div>
                  <span className="text-slate-300">
                    {new Date(s.created_at).toLocaleString()}
                  </span>
                  {s.duration_seconds !== null && (
                    <span className="ml-2 text-xs text-slate-600">
                      {s.duration_seconds}s
                    </span>
                  )}
                  {s.status === "FAILED" && s.error && (
                    <span className="ml-2 text-xs text-red-400">{s.error}</span>
                  )}
                </div>
                <Badge color={statusColor(s.status)}>{s.status}</Badge>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <div className="flex items-center justify-between">
          <SectionTitle>Disclosure contacts</SectionTitle>
          <Button
            variant="secondary"
            onClick={() => discover.mutate()}
            disabled={discover.isPending}
          >
            {discover.isPending ? "Discovering…" : "Discover contacts"}
          </Button>
        </div>
        {contacts.isLoading || !contacts.data ? (
          <Spinner />
        ) : contacts.data.contacts.length === 0 ? (
          <Empty>
            No contacts discovered yet. /.well-known/security.txt and meta-tag
            discovery run without exploits.
          </Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {contacts.data.contacts.map((c) => (
              <div
                key={c.id}
                className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm"
              >
                <div>
                  <span className="text-slate-200">
                    {c.email ?? c.contact_url}
                  </span>
                  <span className="ml-2 text-xs text-slate-600">
                    via {c.source}
                  </span>
                </div>
                <Badge color={c.confidence === "HIGH" ? "green" : "neutral"}>
                  {c.confidence}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </Card>

      <p className="text-center text-xs text-slate-600">
        <Link href="/assets" className="hover:text-slate-400">
          ← Back to assets
        </Link>
      </p>
    </div>
  );
}
