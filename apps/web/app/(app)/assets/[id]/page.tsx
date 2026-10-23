"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Globe,
  Radar,
  Search,
  ShieldCheck,
  TriangleAlert,
  UserRoundPlus,
} from "lucide-react";
import { ApiError, api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBanner,
  Spinner,
  TimeAgo,
} from "@/components/ui";
import { PageHeader, SectionHeader } from "@/components/page";
import { ScanStatusBadge } from "@/components/badges";
import { DashboardMetric } from "@/components/metrics";
import { formatDateTime, formatDuration, friendlyScanError } from "@/lib/format";

export default function AssetDetailPage() {
  const { id: assetId } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);

  const asset = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => api.asset(assetId),
    refetchInterval: 15_000,
  });
  const scans = useQuery({
    queryKey: ["asset-scans", assetId],
    queryFn: () => api.scans(assetId, 50),
    refetchInterval: 10_000,
  });
  const contacts = useQuery({
    queryKey: ["asset-contacts", assetId],
    queryFn: () => api.contacts(assetId),
  });
  const findings = useQuery({
    queryKey: ["asset-findings", assetId],
    queryFn: () => api.findings({ asset_id: assetId }),
  });

  const doScan = useMutation({
    mutationFn: () => api.queueScan(assetId),
    onMutate: () => setActionError(null),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset-scans", assetId] });
      qc.invalidateQueries({ queryKey: ["asset", assetId] });
    },
    onError: (e) =>
      setActionError(e instanceof ApiError ? e.message : "Failed to queue scan."),
  });

  /* Discover fix: show backend errors visibly and poll contacts briefly
   * after the async task is queued (202), so results appear without a
   * manual refresh and duplicate clicks are less likely. */
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState<string | null>(null);
  const discover = useMutation({
    mutationFn: () => api.discoverContacts(assetId),
    onMutate: () => {
      setDiscoverError(null);
      setDiscovering(true);
    },
    onSuccess: (ack) => {
      const stop = qc.invalidateQueries({ queryKey: ["asset-contacts", assetId] });
      const t = setInterval(() => {
        qc.invalidateQueries({ queryKey: ["asset-contacts", assetId] });
      }, 4_000);
      setTimeout(() => {
        clearInterval(t);
        setDiscovering(false);
      }, 12_000);
      return stop.finally(() => clearInterval(t));
    },
    onError: (e) => {
      setDiscovering(false);
      setDiscoverError(
        e instanceof ApiError
          ? e.message
          : "Contact discovery failed to start. Try again — errors are no longer silent.",
      );
    },
  });

  const confirmAuth = useMutation({
    mutationFn: (v: boolean) => api.updateAsset(assetId, { authorization_confirmed: v }),
    onMutate: () => setActionError(null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["asset", assetId] }),
    onError: (e) =>
      setActionError(e instanceof ApiError ? e.message : "Failed to update asset."),
  });

  if (asset.isLoading) {
    return (
      <div className="p-6">
        <Spinner label="Loading asset…" />
      </div>
    );
  }
  if (asset.isError || !asset.data) {
    return (
      <div className="max-w-2xl p-6">
        <Empty icon={<Globe className="h-8 w-8" aria-hidden />}>
          Asset not found (or not yours).{" "}
          <Link href="/assets" className="text-accent hover:underline">
            Back to assets
          </Link>
        </Empty>
      </div>
    );
  }
  const a = asset.data;
  const contactCount = contacts.data?.contacts.length ?? 0;
  const openFindings =
    findings.data?.findings.filter((f) => f.status.startsWith("OPEN")).length ??
    a.open_findings ??
    0;
  const lastScan: Scan | undefined = scans.data?.scans[0];

  return (
    <div className="mx-auto max-w-[1400px] p-6">
      <Link
        href="/assets"
        className="inline-flex items-center gap-1 text-xs text-ink-3 transition-colors hover:text-ink-2"
      >
        <ArrowLeft className="h-3 w-3" aria-hidden /> Back to assets
      </Link>
      <PageHeader
        title={a.name}
        subtitle={
          <span>
            <a href={a.url} className="text-ink-2 underline decoration-line-strong hover:text-ink">
              {a.url}
            </a>
          </span>
        }
        actions={
          <>
            {a.authorization_confirmed ? (
              <Badge color="green">
                <ShieldCheck className="h-3 w-3" aria-hidden /> Authorized
              </Badge>
            ) : (
              <Button variant="secondary" onClick={() => confirmAuth.mutate(true)} disabled={confirmAuth.isPending}>
                <ShieldCheck className="h-4 w-4" aria-hidden />
                {confirmAuth.isPending ? "Confirming…" : "Confirm authorization"}
              </Button>
            )}
            <Button onClick={() => doScan.mutate()} disabled={doScan.isPending}>
              <Radar className="h-4 w-4" aria-hidden />
              {doScan.isPending ? "Queuing…" : "Scan now"}
            </Button>
          </>
        }
      />

      {a.description ? <p className="mt-2 text-sm text-ink-2">{a.description}</p> : null}

      {actionError ? <div className="mt-4"><ErrorBanner message={actionError} /></div> : null}

      {/* Metric strip */}
      <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <DashboardMetric
          label="Open findings"
          value={openFindings}
          icon={TriangleAlert}
          accent={openFindings > 0 ? "red" : "green"}
          href={`/findings?asset_id=${assetId}&status=OPEN%2COPEN_RISK_ACCEPTED%2COPEN_TRACKED`}
        />
        <DashboardMetric
          label="Scans"
          value={scans.data?.scans.length ?? "—"}
          icon={Radar}
          accent="blue"
          href={`/scans?asset_id=${assetId}`}
        />
        <DashboardMetric
          label="Contacts"
          value={contactCount}
          icon={UserRoundPlus}
          accent={contactCount > 0 ? "green" : "amber"}
        />
        <Card className="col-span-2 lg:col-span-1">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-ink-2">Monitoring</span>
            <Badge color={a.monitoring_enabled ? "green" : "neutral"}>
              {a.monitoring_enabled ? "enabled" : "paused"}
            </Badge>
          </div>
          <div className="mt-2 flex flex-col gap-1 text-[11px] text-ink-3">
            <span>Interval: {Math.round(a.scan_interval_seconds / 3600)}h</span>
            <span>
              Last: {a.last_scan_at ? <TimeAgo date={a.last_scan_at} /> : "never"}
            </span>
            <span>
              Next: {a.next_scan_at ? formatDateTime(a.next_scan_at) : "—"}
              {!a.authorization_confirmed ? " (pending authorization)" : ""}
            </span>
          </div>
        </Card>
      </div>

      {/* Scan history */}
      <Card className="mt-6">
        <SectionHeader title="Scan history" />
        {scans.isLoading || !scans.data ? (
          <Spinner />
        ) : scans.data.scans.length === 0 ? (
          <Empty icon={<Radar className="h-8 w-8" aria-hidden />}>
            No scans yet — run the first one now.
          </Empty>
        ) : (
          <ul className="divide-y divide-line">
            {scans.data.scans.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-ink-2">{formatDateTime(s.created_at)}</span>
                  {s.duration_seconds !== null && s.status === "COMPLETED"
                    ? <span className="text-xs text-ink-3">{formatDuration(s.duration_seconds)}</span>
                    : null}
                  {s.status === "FAILED" && s.error ? (
                    <span className="text-xs text-crit">{friendlyScanError(s.error)}</span>
                  ) : null}
                </span>
                <span className="flex items-center gap-2">
                  <ScanStatusBadge status={s.status} />
                </span>
              </li>
            ))}
          </ul>
        )}
        {lastScan ? (
          <p className="mt-2 text-[11px] text-ink-3">
            Latest known state: {formatDateTime(lastScan.created_at)} — resumed
            monitoring picks the schedule automatically after authorization.
          </p>
        ) : null}
      </Card>

      {/* Contacts */}
      <Card className="mt-6">
        <SectionHeader
          title="Disclosure contacts"
          children={
            <span className="flex items-center gap-2">
              {discoverError ? (
                <span className="text-xs text-crit">{discoverError}</span>
              ) : discovering ? (
                <span className="flex items-center gap-1.5 text-xs text-accent">
                  <Spinner label="" />
                  discovering…
                </span>
              ) : null}
              <Button
                variant="secondary"
                size="sm"
                onClick={() => discover.mutate()}
                disabled={discover.isPending || discovering}
              >
                <Search className="h-3.5 w-3.5" aria-hidden />
                {discovering ? "Discovering…" : "Discover contacts"}
              </Button>
            </span>
          }
        />
        {contacts.isLoading || !contacts.data ? (
          <Spinner />
        ) : contacts.data.contacts.length === 0 ? (
          <Empty icon={<UserRoundPlus className="h-8 w-8" aria-hidden />}>
            No contacts discovered yet. /.well-known/security.txt and meta-tag
            discovery run without exploits.
          </Empty>
        ) : (
          <ul className="divide-y divide-line">
            {contacts.data.contacts.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-ink">
                    {c.email ?? c.contact_url}
                  </span>
                  <span className="text-xs text-ink-3">
                    via {c.source.replace("_", " ").toLowerCase()}
                  </span>
                  {c.encryption_url || c.policy_url ? (
                    <span className="text-xs text-ink-3">
                      · policy/encryption published
                    </span>
                  ) : null}
                </span>
                <span className="flex items-center gap-2">
                  <Badge color={c.confidence === "HIGH" ? "green" : "neutral"}>
                    {c.confidence} confidence
                  </Badge>
                  <TimeAgo date={c.discovered_at} className="text-[11px] text-ink-3" />
                </span>
              </li>
            ))}
          </ul>
        )}

      </Card>
    </div>
  );
}
