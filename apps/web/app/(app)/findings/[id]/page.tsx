"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  BookOpen,
  CheckCircle2,
  FileWarning,
  FlaskConical,
  History,
  Send,
  Wrench,
} from "lucide-react";
import { ApiError, api } from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBanner,
  Spinner,
  TimeAgo,
} from "@/components/ui";
import {
  FindingStatusBadge,
  SeverityBadge,
} from "@/components/badges";
import { formatDateTime, formatDuration } from "@/lib/format";

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const f = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.finding(id),
    refetchInterval: 15_000,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["finding", id] });
    qc.invalidateQueries({ queryKey: ["findings"] });
    qc.invalidateQueries({ queryKey: ["metrics"] });
  };

  const verify = useMutation({
    mutationFn: () => api.rescanFinding(id as string),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["asset-scans"] });
      invalidate();
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Verification failed to start."),
  });

  const close = useMutation({
    mutationFn: () => api.closeFinding(id as string),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Cannot close finding."),
  });

  const draft = useMutation({
    mutationFn: () => api.draftDisclosure(id as string),
    onSuccess: (d) => {
      setError(null);
      router.push(`/disclosures/${d.id}`);
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : "Could not create draft."),
  });

  if (f.isLoading) {
    return (
      <div className="p-6">
        <Spinner label="Loading finding…" />
      </div>
    );
  }
  if (f.isError || !f.data) {
    return (
      <div className="max-w-2xl p-6">
        <Empty icon={<FileWarning className="h-8 w-8" aria-hidden />}>
          Finding not found (or not yours).{" "}
          <Link href="/findings" className="text-blue-400 hover:underline">
            Back to findings
          </Link>
        </Empty>
      </div>
    );
  }
  const d = f.data;

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <Link
        href="/findings"
        className="inline-flex items-center gap-1 text-xs text-slate-500 transition-colors hover:text-slate-300"
      >
        <ArrowLeft className="h-3 w-3" aria-hidden /> Back to findings
      </Link>

      <header className="mt-3 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={d.severity} />
            <FindingStatusBadge status={d.status} />
            <Badge color="neutral">{d.vulnerability_id}</Badge>
            {d.cvss !== null && <Badge color="info">CVSS {d.cvss}</Badge>}
          </div>
          <h1 className="mt-1.5 text-xl font-semibold tracking-[-0.01em] text-slate-100">
            {d.title}
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            On{" "}
            <Link href={`/assets/${d.asset_id}`} className="text-slate-300 hover:text-blue-300">
              {d.asset_name}
            </Link>
            {" · "}detected {formatDateTime(d.first_seen)}
          </p>
        </div>
        <div className="flex flex-col gap-2">
          <Button onClick={() => draft.mutate()} disabled={draft.isPending}>
            <Send className="h-4 w-4" aria-hidden />
            {draft.isPending ? "Drafting…" : "Prepare disclosure"}
          </Button>
          <Button variant="secondary" onClick={() => verify.mutate()} disabled={verify.isPending}>
            <FlaskConical className="h-4 w-4" aria-hidden />
            {verify.isPending ? "Queuing…" : "Verify fix (rescan)"}
          </Button>
          <Button variant="danger" onClick={() => close.mutate()} disabled={close.isPending}>
            {close.isPending ? "Closing…" : "Close finding"}
          </Button>
        </div>
      </header>

      {error ? <div className="mt-4"><ErrorBanner message={error} /></div> : null}

      {/* Version condition strip */}
      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        <Card className="p-4">
          <span className="text-xs text-slate-500">Detected version</span>
          <div className="mt-1 font-mono text-base font-semibold text-[var(--sev-critical)]">
            {d.detected_version ?? "unknown"}
          </div>
        </Card>
        <Card className="p-4">
          <span className="text-xs text-slate-500">Fixed version</span>
          <div className="mt-1 font-mono text-base font-semibold text-[var(--status-ok)]">
            {d.fixed_version ?? "— not published / unknown"}
          </div>
        </Card>
        <Card className="p-4">
          <span className="text-xs text-slate-500">Vendor patch</span>
          <div className="mt-1">
            {d.vendor_patch_possible === true ? (
              <Badge color="green"><CheckCircle2 className="h-3 w-3" aria-hidden /> Upgrade possible</Badge>
            ) : d.vendor_patch_possible === false ? (
              <Badge color="neutral">No upgrade path</Badge>
            ) : (
              <Badge color="neutral">Unknown</Badge>
            )}
          </div>
        </Card>
      </div>

      {/* Narrative sections */}
      <div className="mt-6 grid gap-4 xl:grid-cols-2">
        <Card>
          <section aria-labelledby="h-summary">
            <h2 id="h-summary" className="flex items-center gap-2 text-sm font-semibold text-slate-200">
              <FileWarning className="h-4 w-4 text-slate-500" aria-hidden /> Summary
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-300">{d.summary}</p>
            <h2 id="h-impact" className="mt-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
              <FileWarning className="h-4 w-4 text-slate-500" aria-hidden /> Impact
            </h2>
            <p className="mt-2 text-sm leading-6 text-[var(--sev-high)]">{d.impact}</p>
          </section>
        </Card>
        <Card>
          <section aria-labelledby="h-rem">
            <h2 id="h-rem" className="flex items-center gap-2 text-sm font-semibold text-slate-200">
              <Wrench className="h-4 w-4 text-slate-500" aria-hidden /> Remediation
            </h2>
            <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">{d.remediation}</p>
            {d.references && d.references.length > 0 ? (
              <>
                <h2 id="h-refs" className="mt-5 flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <BookOpen className="h-4 w-4 text-slate-500" aria-hidden /> References
                </h2>
                <ul className="mt-2 flex flex-col gap-1 text-xs">
                  {d.references.map((r) => (
                    <li key={r}>
                      <a
                        href={r}
                        target="_blank"
                        rel="noreferrer"
                        className="break-all text-blue-400 hover:underline"
                      >
                        {r}
                      </a>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </section>
        </Card>
      </div>

      {/* Evidence */}
      <Card className="mt-6">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <FlaskConical className="h-4 w-4 text-slate-500" aria-hidden /> Evidence — non-invasive
        </h2>
        {d.evidence && d.evidence.length > 0 ? (
          <>
            <div className="mt-3 flex flex-col gap-2">
              {d.evidence.map((e) => (
                <div key={e.id} className="card-flat p-3 text-sm">
                  <div className="mb-1.5 flex flex-wrap items-center gap-2 text-xs">
                    <Badge color="neutral">{e.type}</Badge>
                    <span className="font-medium text-slate-300">{e.name}</span>
                    <span className="ml-auto text-slate-600">
                      {e.confidence} · <TimeAgo date={e.collected_at} className="" />
                      {e.source ? ` · via ${e.source}` : ""}
                    </span>
                  </div>
                  <pre className="whitespace-pre-wrap break-all font-mono text-xs text-slate-300">
                    {e.value}
                  </pre>
                </div>
              ))}
            </div>
            <p className="mt-3 border-l-2 border-[rgba(255,255,255,0.1)] pl-3 text-[11px] leading-5 text-slate-500">
              No exploitation was performed. Findings never exceed HIGH_CONFIDENCE
              from remote non-invasive assessment alone — this evidence shows a
              version condition met on a public endpoint, not a proven
              exploitable path.
            </p>
          </>
        ) : (
          <Empty>No evidence recorded.</Empty>
        )}
      </Card>

      {/* Detection timeline */}
      <div className="mt-6 grid gap-4 xl:grid-cols-2">
        <Card className="p-4">
          <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <History className="h-3.5 w-3.5" aria-hidden /> Timeline
          </h2>
          <dl className="mt-3 grid gap-1.5 text-xs">
            <div className="flex justify-between gap-2"><dt className="text-slate-500">First seen</dt><dd className="text-slate-300">{formatDateTime(d.first_seen)}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-slate-500">Last seen</dt><dd className="text-slate-300">{formatDateTime(d.last_seen)}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-slate-500">Detection method</dt><dd className="font-mono text-[11px] text-slate-300">{d.detection_method}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-slate-500">Scanner</dt><dd className="font-mono text-[11px] text-slate-300">v{d.scanner_version}</dd></div>
            {d.resolved_at ? (
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Resolved</dt><dd className="text-[var(--status-ok)]">{formatDateTime(d.resolved_at)}</dd></div>
            ) : null}
          </dl>
        </Card>
        <Card>
          <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <Send className="h-3.5 w-3.5" aria-hidden /> Disclosures
          </h2>
          {d.disclosures && d.disclosures.length > 0 ? (
            <ul className="mt-3 divide-y divide-[rgba(255,255,255,0.06)]">
              {d.disclosures.map((x) => (
                <li key={x.id}>
                  <Link
                    href={`/disclosures/${x.id}`}
                    className="flex items-center justify-between gap-2 py-2.5 text-sm transition-colors hover:text-slate-100"
                  >
                    <span className="truncate text-slate-300">
                      {x.recipient_email ?? "(no recipient)"}
                    </span>
                    <Badge color={x.status === "DELIVERED" ? "green" : "neutral"}>
                      {x.status}
                      {x.delivery_status ? ` · ${x.delivery_status}` : ""}
                    </Badge>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-slate-500">
              No disclosures drafted for this finding yet — “Prepare disclosure”
              creates the first draft.
            </p>
          )}
        </Card>
      </div>
    </div>
  );
}
