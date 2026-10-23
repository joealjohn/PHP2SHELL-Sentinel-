"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Plus, ShieldCheck, TriangleAlert } from "lucide-react";
import { ApiError, api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { Badge, Button, Card, Empty, ErrorBanner, NowStamp, Skeleton, Spinner, TimeAgo } from "@/components/ui";
import { PageHeader, SectionHeader } from "@/components/page";
import { ScanStatusBadge } from "@/components/badges";

export default function AssetsPage() {
  const router = useRouter();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["assets"],
    queryFn: () => api.assets(),
    refetchInterval: 30_000,
  });

  /* Backend exposes last_scan_status but it is currently always null
   * (known serializer gap); derive it honestly from the scans list. */
  const scansQ = useQuery({
    queryKey: ["scans", "asset-badges"],
    queryFn: () => api.scans(undefined, 200),
    refetchInterval: 30_000,
  });
  const latestStatus = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of scansQ.data?.scans ?? []) {
      if (!m.has(s.asset_id)) m.set(s.asset_id, s.status);
    }
    return m;
  }, [scansQ.data]);

  const scan = useMutation({
    mutationFn: (asset: Asset) => api.queueScan(asset.id),
    onSuccess: (_d, asset) => router.push(`/assets/${asset.id}`),
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to queue scan."),
  });

  const del = useMutation({
    mutationFn: (asset: Asset) => api.deleteAsset(asset.id),
    onSuccess: () => {
      setError(null);
      refetch();
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to delete asset."),
  });

  const assets = data?.assets ?? [];

  return (
    <div className="mx-auto max-w-[1400px] p-6">
      <PageHeader
        title="Assets"
        subtitle="Hosts under active monitoring. Only add targets you own or are authorized to test."
        actions={
          <Link href="/assets/new">
            <Button size="md">
              <Plus className="h-4 w-4" aria-hidden /> Add asset
            </Button>
          </Link>
        }
      />

      {error ? <div className="mt-4"><ErrorBanner message={error} /></div> : null}

      <div className="mt-6">
        <SectionHeader title={`${assets.length} asset${assets.length === 1 ? "" : "s"}`}>
          {isLoading ? <Spinner label="Loading…" /> : null}
        </SectionHeader>
        <Card className="overflow-x-auto">
          {isError ? (
            <ErrorBanner message="Could not load assets." />
          ) : isLoading || !data ? (
            <div className="flex flex-col gap-3 p-1">
              {[0, 1, 2].map((i) => <Skeleton key={i} className="h-11 w-full" />)}
            </div>
          ) : assets.length === 0 ? (
            <Empty icon={<Globe className="h-8 w-8" aria-hidden />}>
              No assets yet.{" "}
              <Link href="/assets/new" className="text-accent hover:underline">
                Add your first target
              </Link>{" "}
              to start monitoring.
            </Empty>
          ) : (
            <table className="w-full min-w-[720px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Asset</th>
                  <th className="th">Authorization</th>
                  <th className="th">Last scan</th>
                  <th className="th text-right">Open findings</th>
                  <th className="th text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => (
                  <tr
                    key={a.id}
                    className="border-b border-line transition-colors last:border-0 hover:bg-raised"
                  >
                    <td className="td">
                      <Link
                        href={`/assets/${a.id}`}
                        className="font-medium text-ink hover:text-accent"
                      >
                        {a.name}
                      </Link>
                      <div className="truncate text-xs text-ink-3">{a.host}</div>
                    </td>
                    <td className="td">
                      {a.authorization_confirmed ? (
                        <Badge color="green">
                          <ShieldCheck className="h-3 w-3" aria-hidden /> Confirmed
                        </Badge>
                      ) : (
                        <Badge color="amber">
                          <TriangleAlert className="h-3 w-3" aria-hidden /> Not confirmed
                        </Badge>
                      )}
                    </td>
                    <td className="td">
                      {latestStatus.get(a.id) ? (
                        <span className="flex flex-col gap-0.5">
                          <ScanStatusBadge status={latestStatus.get(a.id)!} />
                          {a.last_scan_at ? (
                            <TimeAgo date={a.last_scan_at} className="text-[10px] text-ink-3" />
                          ) : null}
                        </span>
                      ) : a.last_scan_at ? (
                        <TimeAgo date={a.last_scan_at} className="text-ink-3" />
                      ) : (
                        <span className="text-ink-3">never scanned</span>
                      )}
                    </td>
                    <td className="td text-right">
                      {a.open_findings != null && a.open_findings > 0 ? (
                        <Link
                          href={`/findings?asset_id=${a.id}&status=OPEN%2COPEN_RISK_ACCEPTED%2COPEN_TRACKED`}
                        >
                          <Badge color="CRITICAL">{a.open_findings} open</Badge>
                        </Link>
                      ) : (
                        <span className="text-ink-3">0</span>
                      )}
                    </td>
                    <td className="td text-right">
                      <span className="inline-flex justify-end gap-1.5">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => scan.mutate(a)}
                          disabled={scan.isPending}
                        >
                          {scan.isPending && scan.variables?.id === a.id
                            ? "Queuing…"
                            : "Scan now"}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            if (confirm(`Delete asset "${a.name}"? Scans and findings are kept in audit history.`)) {
                              del.mutate(a);
                            }
                          }}
                        >
                          Delete
                        </Button>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <p className="mt-3 text-[11px] text-ink-3">
          Last checked <NowStamp /> ·
          SSRF guards block private, loopback, and metadata targets unless
          SCAN_ALLOW_PRIVATE_TARGETS is set for lab testing.
        </p>
      </div>
    </div>
  );
}
