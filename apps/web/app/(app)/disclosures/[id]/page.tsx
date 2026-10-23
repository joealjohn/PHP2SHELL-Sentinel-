"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  BadgeCheck,
  CheckCircle2,
  Clock,
  Cog,
  FileText,
  Send,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { ApiError, api } from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBanner,
  Input,
  Spinner,
  Textarea,
  TimeAgo,
} from "@/components/ui";
import { PageHeader, SectionHeader } from "@/components/page";
import { DisclosureStatusBadge } from "@/components/badges";
import { disclosureStatusLabel, formatDateTime } from "@/lib/format";

const FLOW = [
  { key: "DRAFT", hint: "Edit the draft freely." },
  { key: "PENDING_APPROVAL", hint: "Awaiting your review." },
  { key: "APPROVED", hint: "Approved — ready to send." },
  { key: "SENT", hint: "Handed to SMTP." },
  { key: "DELIVERED", hint: "Accepted by the recipient server." },
];

export default function DisclosureDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["disclosure", id],
    queryFn: () => api.disclosure(id as string),
    refetchInterval: 15_000,
  });

  const [subject, setSubject] = useState<string | null>(null);
  const [body, setBody] = useState<string | null>(null);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["disclosure", id] });
    qc.invalidateQueries({ queryKey: ["disclosures"] });
  };
  const wrap = (fn: () => Promise<unknown>, ok?: string) =>
    fn()
      .then(() => {
        setError(null);
        if (ok) setInfo(ok);
        invalidate();
      })
      .catch((e: unknown) =>
        setError(e instanceof ApiError ? e.message : "Request failed."),
      );

  const edit = useMutation({
    mutationFn: () =>
      api.editDisclosure(id as string, {
        subject: subject ?? q.data?.subject ?? "",
        body: body ?? q.data?.body ?? "",
      }),
    onSuccess: () => {
      setError(null);
      setSubject(null);
      setBody(null);
      setInfo("Draft saved.");
      invalidate();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : "Edit failed."),
  });

  if (q.isLoading) {
    return (
      <div className="p-6">
        <Spinner label="Loading disclosure…" />
      </div>
    );
  }
  if (q.isError || !q.data) {
    return (
      <div className="max-w-2xl p-6">
        <Empty icon={<FileText className="h-8 w-8" aria-hidden />}>
          Disclosure not found (or not yours).{" "}
          <Link href="/disclosures" className="text-accent hover:underline">
            Back to disclosures
          </Link>
        </Empty>
      </div>
    );
  }
  const d = q.data;
  const editable = d.status === "DRAFT";
  const effSubject = subject ?? d.subject;
  const effBody = body ?? d.body;
  const cancelled = d.status === "CANCELLED";

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <Link
        href="/disclosures"
        className="inline-flex items-center gap-1 text-xs text-ink-3 transition-colors hover:text-ink-2"
      >
        <ArrowLeft className="h-3 w-3" aria-hidden /> Back to disclosures
      </Link>

      <header className="mt-3 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <DisclosureStatusBadge status={d.status} />
            {d.delivery_status ? <Badge color="info">delivery: {d.delivery_status}</Badge> : null}
          </div>
          <h1 className="mt-1.5 text-xl font-semibold tracking-[-0.01em] text-ink">
            {d.subject}
          </h1>
          <p className="mt-1 text-sm text-ink-2">
            <Link href={`/assets/${d.asset_id}`} className="hover:text-ink">
              {d.asset_name}
            </Link>
            {" → "}
            <span className="font-mono text-xs">{d.recipient_email}</span>
            {d.recipient_source ? (
              <span className="text-ink-3">
                {" "}· source: {d.recipient_source.replace("_", " ").toLowerCase()}
              </span>
            ) : null}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {editable ? (
            <>
              <Button variant="secondary" onClick={() => wrap(() => api.testEmail(d.id), "Test email sent to your own account address.")}>
                <Send className="h-4 w-4" aria-hidden /> Send test email
              </Button>
              <Button variant="secondary" onClick={() => wrap(() => api.markPending(d.id))}>
                <Clock className="h-4 w-4" aria-hidden /> Mark pending
              </Button>
              <Button onClick={() => wrap(() => api.approve(d.id))}>
                <BadgeCheck className="h-4 w-4" aria-hidden /> Approve &amp; send
              </Button>
              <Button variant="danger" onClick={() => wrap(() => api.cancelDisclosure(d.id))}>
                Cancel
              </Button>
            </>
          ) : d.status === "PENDING_APPROVAL" ? (
            <>
              <Button
                variant="secondary"
                onClick={() => wrap(() => api.markPending(d.id))}
                disabled
              >
                <Clock className="h-4 w-4" aria-hidden /> Pending approval
              </Button>
              <Button onClick={() => wrap(() => api.approve(d.id))}>
                <BadgeCheck className="h-4 w-4" aria-hidden /> Approve &amp; send
              </Button>
              <Button variant="danger" onClick={() => wrap(() => api.cancelDisclosure(d.id))}>
                Cancel
              </Button>
            </>
          ) : ["APPROVED", "SENT", "DELIVERED"].includes(d.status) ? (
            <>
              <Button variant="secondary" onClick={() => wrap(() => api.sendNow(d.id))}>
                <Send className="h-4 w-4" aria-hidden /> Send again
              </Button>
              {d.status !== "DELIVERED" ? (
                <Button variant="danger" onClick={() => wrap(() => api.cancelDisclosure(d.id))}>
                  Cancel
                </Button>
              ) : null}
            </>
          ) : (
            <Badge color="neutral">No further actions — {disclosureStatusLabel[d.status] ?? d.status}</Badge>
          )}
        </div>
      </header>

      {cancelled || d.error || d.delivery_status === "FAILED" ? (
        <div className="mt-4">
          <ErrorBanner
            message={
              cancelled
                ? "This disclosure was cancelled and cannot be sent again. Draft a new one from the finding."
                : (d.error ? `Delivery error: ${d.error}` : "Delivery failed — see API logs for the SMTP trace.")
            }
          />
        </div>
      ) : info ? (
        <div className="mt-4 flex items-center gap-2 rounded-lg border border-ok/30 bg-ok/10 px-3 py-2 text-sm text-ok">
          <CheckCircle2 className="h-4 w-4" aria-hidden /> {info}
        </div>
      ) : null}

      {/* Status flow rail */}
      <Card className="mt-6">
        <SectionHeader title="Workflow" />
        <ol className="flex flex-wrap gap-x-2 gap-y-3">
          {FLOW.map((s, i) => {
            const idx = FLOW.findIndex((x) => x.key === d.status);
            const done = idx >= i && idx !== -1;
            const active = idx === i;
            return (
              <li key={s.key} className="flex min-w-[130px] flex-1 items-center gap-2">
                <span
                  className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold ${
                    done
                      ? "border-ok/40 bg-ok/10 text-ok"
                      : active
                        ? "border-accent/50 bg-accent/10 text-accent"
                        : "border-line-strong text-ink-3"
                  }`}
                >
                  {done ? <CheckCircle2 className="h-3 w-3" aria-hidden /> : i + 1}
                </span>
                <span className="min-w-0">
                  <span className={`block text-xs font-medium ${done || active ? "text-ink" : "text-ink-3"}`}>
                    {disclosureStatusLabel[s.key]}
                  </span>
                  <span className="block truncate text-[10px] text-ink-3">{s.hint}</span>
                </span>
              </li>
            );
          })}
        </ol>
      </Card>

      {/* Editor */}
      {editable ? (
        <Card className="mt-6">
          <SectionHeader title="Edit draft" />
          <div className="flex flex-col gap-3">
            <Input
              aria-label="Email subject"
              value={effSubject}
              onChange={(e) => setSubject(e.target.value)}
            />
            <Textarea rows={14} aria-label="Email body" value={effBody} onChange={(e) => setBody(e.target.value)} />
            <div className="flex items-center gap-3">
              <Button
                onClick={() => edit.mutate()}
                disabled={edit.isPending || (!subject && !body)}
              >
                {edit.isPending ? "Saving…" : "Save changes"}
              </Button>
              <span className="text-[11px] text-ink-3">
                <Cog className="mr-1 inline h-3 w-3" aria-hidden />
                Protected words (the non-invasive statement) stay enforced by the
                API — edits removing them are rejected.
              </span>
            </div>
          </div>
        </Card>
      ) : null}

      {/* Static preview for the email */}
      <Card className="mt-6">
        <SectionHeader title={editable ? "Effective content" : "Sent content"} />
        <div className="rounded-lg border border-line bg-[var(--bg-page)] p-4">
          <div className="mb-3 border-b border-line pb-2 text-xs">
            <span className="text-ink-3">Subject:</span>{" "}
            <span className="font-medium text-ink">{d.subject}</span>
          </div>
          <pre className="whitespace-pre-wrap font-sans text-xs leading-5 text-ink-2">
            {d.body}
          </pre>
        </div>
      </Card>

      {/* Meta timeline */}
      <Card className="mt-6 p-4">
        <div className="flex flex-wrap gap-x-8 gap-y-2 text-[11px]">
          <span className="text-ink-3">
            Created <TimeAgo date={d.created_at} className="text-ink-2" /> ({formatDateTime(d.created_at)})
          </span>
          {d.approved_at ? (
            <span className="text-ink-3">
              Approved <TimeAgo date={d.approved_at} className="text-ink-2" />
            </span>
          ) : null}
          {d.last_sent_at ? (
            <span className="text-ink-3">
              Last sent <TimeAgo date={d.last_sent_at} className="text-ink-2" />
            </span>
          ) : null}
          <span className="flex items-center gap-1.5 text-ink-3">
            <ShieldCheck className="h-3 w-3" aria-hidden /> Token-gated delivery · auto-cancel after 72h · no exploit claims
          </span>
          {!editable && !d.error ? (
            <span className="flex items-center gap-1.5 text-ink-3">
              <TriangleAlert className="h-3 w-3" aria-hidden />
              Duplicate sends are blocked by the backend with 409 DUPLICATE_DISCLOSURE
            </span>
          ) : null}
        </div>
      </Card>
    </div>
  );
}
