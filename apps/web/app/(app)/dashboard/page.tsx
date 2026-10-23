"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Bell,
  CheckCircle2,
  CircleDot,
  Globe,
  Send,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import { Card, Empty, ErrorBanner, NowStamp, Spinner, TimeAgo } from "@/components/ui";
import { PageHeader, SectionHeader } from "@/components/page";
import {
  ActivityItem,
  DashboardMetric,
  RiskIndicator,
  SeverityOverview,
} from "@/components/metrics";
import { ScanActivityChart, scanDays } from "@/components/chart";
import {
  FindingStatusBadge,
  ScanStatusBadge,
  SeverityBadge,
} from "@/components/badges";
import { formatDuration, scanStatusLabel } from "@/lib/format";

export default function DashboardPage() {
  const metrics = useQuery({
    queryKey: ["metrics"],
    queryFn: () => api.metrics(),
    refetchInterval: 60_000,
  });
  const scans = useQuery({
    queryKey: ["scans", "chart"],
    queryFn: () => api.scans(undefined, 200),
    refetchInterval: 60_000,
  });

  if (metrics.isLoading || !metrics.data) {
    return (
      <div className="p-6">
        <Spinner label="Loading dashboard…" />
      </div>
    );
  }
  if (metrics.isError) {
    return (
      <div className="p-6">
        <ErrorBanner message="Could not load dashboard data. Is the API running?" />
      </div>
    );
  }

  const m = metrics.data;
  const days = scanDays(scans.data?.scans ?? [], 14);
  const totalScans = days.reduce((a, d) => a + d.completed + d.failed + d.other, 0);
  const failedScans = days.reduce((a, d) => a + d.failed, 0);
  const assetsNeedingAttention = m.recent_assets.filter(
    (a) => a.open_findings != null && a.open_findings > 0,
  ).length;

  return (
    <div className="mx-auto max-w-[1400px] p-6">
      <PageHeader
        title="Dashboard"
        subtitle="Live state of your monitored assets — real data only, refreshed every minute."
      />

      {/* Metric row */}
      <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <DashboardMetric
          label="Monitored assets"
          value={m.assets}
          icon={Globe}
          accent="blue"
          href="/assets"
          delta={`${assetsNeedingAttention} with open findings`}
        />
        <DashboardMetric
          label="Open findings"
          value={m.open_findings}
          icon={ShieldAlert}
          accent={
            (m.severity.CRITICAL ?? 0) > 0
              ? "red"
              : (m.severity.HIGH ?? 0) > 0
                ? "amber"
                : "blue"
          }
          href="/findings"
          delta={`${(m.severity.CRITICAL ?? 0) + (m.severity.HIGH ?? 0)} crit+high`}
        />
        <DashboardMetric
          label="Resolved findings"
          value={m.resolved_findings}
          icon={CheckCircle2}
          accent="green"
          href="/findings?status=RESOLVED_PATCHED%2CRESOLVED_FIXED%2CRESOLVED_WONT_FIX%2CRESOLVED_FALSE_POSITIVE"
          delta="patched / fixed / accepted"
        />
        <DashboardMetric
          label="Scans (14d)"
          value={totalScans}
          icon={CircleDot}
          accent={failedScans > 0 ? "amber" : "green"}
          href="/scans"
          delta={failedScans > 0 ? `${failedScans} failed` : "0 failed"}
        />
      </div>

      {/* Posture + chart */}
      <div className="mt-6 grid gap-4 xl:grid-cols-[1fr_1.4fr]">
        <Card>
          <SectionHeader title="Security posture" />
          <RiskIndicator metrics={m} />
          <div className="mt-5 border-t border-line pt-4">
            <SeverityOverview metrics={m} />
          </div>
        </Card>
        <Card>
          <SectionHeader title="Scan activity — last 14 days" />
          {scans.isLoading ? (
            <div className="skeleton h-28 w-full" />
          ) : (
            <ScanActivityChart days={days} />
          )}
        </Card>
      </div>

      {/* Findings + activity */}
      <div className="mt-6 grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <Card>
          <SectionHeader
            title="Recent findings"
            children={
              <Link
                href="/findings"
                className="flex items-center gap-1 text-xs text-accent hover:text-accent"
              >
                View all <ArrowUpRight className="h-3 w-3" aria-hidden />
              </Link>
            }
          />
          {m.recent_findings.length === 0 ? (
            <Empty icon={<ShieldAlert className="h-8 w-8" aria-hidden />}>
              No findings yet. Add an asset and run your first scan.
            </Empty>
          ) : (
            <ul className="divide-y divide-line">
              {m.recent_findings.map((f) => (
                <li key={f.id}>
                  <Link
                    href={`/findings/${f.id}`}
                    className="flex items-center justify-between gap-3 py-2.5 transition-colors hover:bg-raised"
                  >
                    <span className="flex min-w-0 items-center gap-2.5">
                      <SeverityBadge severity={f.severity} />
                      <span className="truncate text-sm text-ink">{f.title}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      <span className="hidden text-xs text-ink-3 sm:inline" title={f.asset_url}>
                        {f.asset_name}
                      </span>
                      <FindingStatusBadge status={f.status} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <SectionHeader title="Recent activity" />
          {m.recent_scans.length === 0 &&
          m.recent_disclosures.length === 0 &&
          m.recent_assets.length === 0 ? (
            <p className="py-6 text-center text-sm text-ink-3">No recent activity yet.</p>
          ) : (
          <ul className="divide-y divide-line">
            {m.recent_scans.slice(0, 3).map((s) => (
              <ActivityItem key={s.id} icon={CircleDot} when={s.created_at}>
                Scan {scanStatusLabel[s.status] ?? s.status}
                {s.asset_name ? (
                  <>
                    {" — "}
                    <Link href={`/assets/${s.asset_id}`} className="text-ink-2 hover:text-ink">
                      {s.asset_name}
                    </Link>
                  </>
                ) : null}
                {s.duration_seconds != null && s.status === "COMPLETED" ? (
                  <span className="text-ink-3"> · {formatDuration(s.duration_seconds)}</span>
                ) : null}
              </ActivityItem>
            ))}
            {m.recent_disclosures.slice(0, 2).map((d) => (
              <ActivityItem
                key={d.id}
                icon={Send}
                when={d.sent_at ?? d.created_at}
                unread={d.status === "SENT" || d.status === "DELIVERED"}
              >
                Disclosure{" "}
                <Link href={`/disclosures/${d.id}`} className="hover:text-ink">
                  {d.finding_title}
                </Link>{" "}
                {d.status === "DELIVERED" ? "delivered to" : d.status === "SENT" ? "sent to" : "is " + (d.status === "PENDING_APPROVAL" ? "pending approval" : d.status.toLowerCase())}
                {d.recipient_email ? (
                  <span className="text-ink-3"> {d.recipient_email}</span>
                ) : null}
              </ActivityItem>
            ))}
            {m.recent_assets.slice(0, 2).map((a) => (
              <ActivityItem key={a.id} icon={Globe} when={a.created_at}>
                Asset{" "}
                <Link href={`/assets/${a.id}`} className="hover:text-ink">
                  {a.name}
                </Link>{" "}
                added to monitoring
              </ActivityItem>
            ))}
          </ul>
          )}
        </Card>
      </div>

      {/* Asset health strip */}
      <Card className="mt-6">
        <SectionHeader
          title="Asset health"
          children={
            <Link
              href="/assets"
              className="flex items-center gap-1 text-xs text-accent hover:text-accent"
            >
              Manage assets <ArrowUpRight className="h-3 w-3" aria-hidden />
            </Link>
          }
        />
        {m.recent_assets.length === 0 ? (
          <Empty icon={<Globe className="h-8 w-8" aria-hidden />}>
            No assets yet —{" "}
            <Link href="/assets/new" className="text-accent hover:underline">
              add your first target
            </Link>
            .
          </Empty>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {m.recent_assets.map((a) => (
              <Link
                key={a.id}
                href={`/assets/${a.id}`}
                className="card flex items-center justify-between gap-3 p-3.5 transition-colors hover:bg-raised"
              >
                <span className="min-w-0">
                  <span className="block truncate text-sm font-medium text-ink">
                    {a.name}
                  </span>
                  <span className="block truncate text-xs text-ink-3">{a.host}</span>
                </span>
                <span className="flex shrink-0 flex-col items-end gap-1">
                  {a.last_scan_status ? (
                    <ScanStatusBadge status={a.last_scan_status} />
                  ) : (
                    <span className="text-[11px] text-ink-3">never scanned</span>
                  )}
                  {a.last_scan_at ? (
                    <TimeAgo date={a.last_scan_at} className="text-[10px] text-ink-3" />
                  ) : null}
                </span>
              </Link>
            ))}
          </div>
        )}
      </Card>

      <p className="mt-6 flex items-start gap-2 text-[11px] leading-4 text-ink-3">
        <Bell className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
        <span>
          Non-invasive scanning only — HIGH_CONFIDENCE is the maximum state a remote
          scanner can assign; exploitability is never claimed. Data shown is the live
          API state as of <NowStamp />.
        </span>
      </p>
      <span className="sr-only">
        <ShieldCheck /> Sentinel dashboard
      </span>
    </div>
  );
}
