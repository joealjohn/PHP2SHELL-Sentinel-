"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  Empty,
  SectionTitle,
  Spinner,
  severityColor,
} from "@/components/ui";

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
    onSuccess: (d) => {
      setError(null);
      router.push("/disclosures");
      qc.invalidateQueries({ queryKey: ["asset-scans"] });
      if (d?.scan_id) void d;
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

  if (f.isLoading) return <Spinner />;
  if (f.isError || !f.data) return <Empty>Finding not found (or not yours).</Empty>;
  const d = f.data;
  const isPatched =
    d.state === "PATCHED" || d.status === "RESOLVED" || d.resolved_at !== null;

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <Badge color={severityColor(d.severity)}>{d.severity}</Badge>
              {isPatched && <Badge color="green">PATCHED / RESOLVED</Badge>}
              <span className="text-xs text-slate-500">{d.vulnerability_id}</span>
              {d.cvss !== null && <Badge color="neutral">CVSS {d.cvss}</Badge>}
            </div>
            <h1 className="text-lg font-semibold text-white">{d.title}</h1>
            <p className="text-xs text-slate-500">
              Asset: {d.asset_name} · Detected: {new Date(d.first_seen).toLocaleString()} ·
              Version {d.detected_version ?? "unknown"} → fixed {d.fixed_version ?? "??"} ·{" "}
              {d.detection_method}
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Button onClick={() => draft.mutate()} disabled={draft.isPending}>
              {draft.isPending ? "Drafting…" : "Prepare disclosure"}
            </Button>
            <Button variant="secondary" onClick={() => verify.mutate()} disabled={verify.isPending}>
              {verify.isPending ? "Queuing…" : "Verify fix (rescan)"}
            </Button>
            <Button variant="danger" onClick={() => close.mutate()} disabled={close.isPending}>
              {close.isPending ? "Closing…" : "Close finding"}
            </Button>
          </div>
        </div>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <SectionTitle>Summary</SectionTitle>
          <p className="text-sm text-slate-300">{d.summary}</p>
          <SectionTitle>Impact</SectionTitle>
          <p className="text-sm text-slate-300">{d.impact}</p>
        </Card>
        <Card>
          <SectionTitle>Remediation</SectionTitle>
          <p className="text-sm text-slate-300">{d.remediation}</p>
          {d.references && d.references.length > 0 && (
            <>
              <SectionTitle>References</SectionTitle>
              <ul className="list-disc pl-5 text-xs text-blue-300">
                {d.references.map((r: string) => (
                  <li key={r}>
                    <a href={r} target="_blank" rel="noreferrer" className="hover:underline">
                      {r}
                    </a>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>
      </div>

      <Card>
        <SectionTitle>Evidence (non-invasive)</SectionTitle>
        {d.evidence && d.evidence.length > 0 ? (
          <div className="space-y-2">
            {d.evidence.map((e) => (
              <div key={e.id} className="rounded-lg border border-[#1f2a3d] p-3 text-sm">
                <div className="mb-1 flex items-center gap-2 text-xs">
                  <Badge color="neutral">{e.type}</Badge>
                  <span className="text-slate-400">{e.name}</span>
                  <span className="ml-auto text-slate-600">
                    {e.confidence} · {new Date(e.collected_at).toLocaleString()}
                  </span>
                </div>
                <pre className="whitespace-pre-wrap break-all text-xs text-slate-300">
                  {e.value}
                </pre>
              </div>
            ))}
            <p className="mt-2 text-[11px] text-slate-600">
              No exploitation was performed. Findings never exceed
              HIGH_CONFIDENCE from remote non-invasive assessment alone.
            </p>
          </div>
        ) : (
          <Empty>No evidence recorded.</Empty>
        )}
      </Card>

      <Card>
        <SectionTitle>Disclosure history</SectionTitle>
        {d.disclosures && d.disclosures.length > 0 ? (
          <div className="divide-y divide-[#1f2a3d]">
            {d.disclosures.map((x) => (
              <Link
                key={x.id}
                href={`/disclosures/${x.id}`}
                className="flex items-center justify-between py-2.5 text-sm hover:opacity-80"
              >
                <span className="text-slate-300">
                  {x.recipient_email ?? "(no recipient)"}
                </span>
                <Badge color={x.status === "DELIVERED" ? "green" : "neutral"}>
                  {x.status}
                  {x.delivery_status ? ` (${x.delivery_status})` : ""}
                </Badge>
              </Link>
            ))}
          </div>
        ) : (
          <Empty>No disclosures drafted for this finding yet.</Empty>
        )}
      </Card>

      <p className="text-center text-xs text-slate-600">
        <Link href="/findings" className="hover:text-slate-400">
          ← Back to findings
        </Link>
      </p>
    </div>
  );
}
