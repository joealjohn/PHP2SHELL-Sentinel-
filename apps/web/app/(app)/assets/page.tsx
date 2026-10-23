"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { Badge, Button, Card, Empty, Input, Spinner } from "@/components/ui";

export default function AssetsPage() {
  const router = useRouter();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [desc, setDesc] = useState("");
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["assets"],
    queryFn: () => api.assets(),
    refetchInterval: 30_000,
  });

  const create = useMutation({
    mutationFn: () =>
      api.createAsset({
        name,
        url,
        description: desc || undefined,
        monitoring_enabled: true,
        authorization_confirmed: authConfirmed,
      }),
    onSuccess: () => {
      setName("");
      setUrl("");
      setDesc("");
      setAuthConfirmed(false);
      setError(null);
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to create asset."),
  });

  const scan = useMutation({
    mutationFn: (asset: Asset) => api.queueScan(asset.id),
    onSuccess: (_d, asset) => router.push(`/assets/${asset.id}`),
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to queue scan."),
  });

  const del = useMutation({
    mutationFn: (asset: Asset) => api.deleteAsset(asset.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }),
  });

  return (
    <div className="space-y-6">
      <Card>
        <h1 className="mb-3 text-lg font-semibold text-white">Add asset</h1>
        <form
          className="grid gap-3 md:grid-cols-[1fr_2fr_auto]"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Input required placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <Input required placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} />
          <Button type="submit" disabled={create.isPending || !authConfirmed}>
            {create.isPending ? "Adding…" : "Add asset"}
          </Button>
          <Input className="md:col-span-3" placeholder="Description (optional)" value={desc} onChange={(e) => setDesc(e.target.value)} />
          <label className="md:col-span-3 flex items-start gap-2 text-xs text-slate-400 cursor-pointer">
            <input
              type="checkbox"
              checked={authConfirmed}
              onChange={(e) => setAuthConfirmed(e.target.checked)}
              className="mt-0.5 size-4 shrink-0 rounded border-[#253a5a] bg-[#0f1f3a] text-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            />
            <span>
              I confirm I own this host or have written authorization to
              security-test it. Required before scans can run.
            </span>
          </label>
        </form>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
        <p className="mt-2 text-[11px] text-slate-600">
          Only add hosts you own or have written authorization to test. SSRF
          guards block private, loopback, and metadata targets unless
          SCAN_ALLOW_PRIVATE_TARGETS is set for lab testing.
        </p>
      </Card>

      <Card>
        <h1 className="mb-3 text-lg font-semibold text-white">Assets</h1>
        {isLoading || !data ? (
          <Spinner />
        ) : data.assets.length === 0 ? (
          <Empty>No assets yet.</Empty>
        ) : (
          <div className="divide-y divide-[#1f2a3d]">
            {data.assets.map((a) => (
              <div key={a.id} className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm">
                <div className="min-w-0">
                  <Link href={`/assets/${a.id}`} className="font-medium text-slate-100 hover:text-blue-300">
                    {a.name}
                  </Link>
                  <div className="truncate text-xs text-slate-500">{a.host}</div>
                </div>
                <div className="flex items-center gap-2">
                  {a.open_findings !== null && a.open_findings > 0 && (
                    <Badge color="CRITICAL">{a.open_findings} open</Badge>
                  )}
                  {a.last_scan_status && (
                    <Badge color={a.last_scan_status === "COMPLETED" ? "green" : "CRITICAL"}>
                      {a.last_scan_status}
                    </Badge>
                  )}
                  {a.monitoring_enabled && <Badge color="neutral">monitored</Badge>}
                  <Button variant="secondary" onClick={() => scan.mutate(a)} disabled={scan.isPending}>
                    {scan.isPending && scan.variables?.id === a.id ? "Queuing…" : "Scan now"}
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => {
                      if (confirm(`Delete asset "${a.name}"?`)) del.mutate(a);
                    }}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
