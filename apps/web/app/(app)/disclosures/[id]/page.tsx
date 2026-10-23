"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api";
import { Badge, Button, Card, Empty, Input, SectionTitle, Spinner, Textarea } from "@/components/ui";

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
  const wrap = (fn: () => Promise<unknown>) =>
    fn()
      .then(() => {
        setError(null);
        invalidate();
      })
      .catch((e: unknown) =>
        setError(
          e instanceof ApiError ? e.message : "Request failed.",
        ),
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
      invalidate();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : "Edit failed."),
  });

  if (q.isLoading) return <Spinner />;
  if (q.isError || !q.data) return <Empty>Disclosure not found (or not yours).</Empty>;
  const d = q.data;
  const editable = d.status === "DRAFT";
  const effSubject = subject ?? d.subject;
  const effBody = body ?? d.body;

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="mb-1 flex items-center gap-2">
              <Badge color={d.status === "DELIVERED" ? "green" : "neutral"}>
                {d.status}
              </Badge>
              {d.delivery_status && (
                <span className="text-xs text-slate-500">
                  delivery: {d.delivery_status}
                </span>
              )}
            </div>
            <h1 className="text-lg font-semibold text-white">{d.subject}</h1>
            <p className="text-xs text-slate-500">
              {d.asset_name} → {d.recipient_email} (source:{" "}
              {d.recipient_source ?? "unknown"})
            </p>
            {d.error && <p className="mt-1 text-xs text-red-400">{d.error}</p>}
            {info && <p className="mt-1 text-xs text-emerald-400">{info}</p>}
          </div>

          <div className="flex flex-wrap gap-2">
            {editable && (
              <Button variant="secondary" onClick={() => wrap(() => api.markPending(d.id))}>
                Mark pending
              </Button>
            )}
            {editable && (
              <Button
                variant="secondary"
                onClick={() =>
                  wrap(() => api.testEmail(d.id)).then(() =>
                    setInfo("Test email sent to your own account address."),
                  )
                }
              >
                Send test email
              </Button>
            )}
            {(d.status === "DRAFT" || d.status === "PENDING_APPROVAL") && (
              <Button onClick={() => wrap(() => api.approve(d.id))}>
                Approve &amp; send
              </Button>
            )}
            {["APPROVED", "SENT", "DELIVERED"].includes(d.status) && (
              <Button variant="secondary" onClick={() => wrap(() => api.sendNow(d.id))}>
                Send again
              </Button>
            )}
            {!["SENT", "DELIVERED"].includes(d.status) && (
              <Button variant="danger" onClick={() => wrap(() => api.cancelDisclosure(d.id))}>
                Cancel
              </Button>
            )}
          </div>
        </div>
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
      </Card>

      {editable && (
        <Card>
          <SectionTitle>Edit draft</SectionTitle>
          <div className="space-y-3">
            <Input value={effSubject} onChange={(e) => setSubject(e.target.value)} />
            <Textarea rows={14} value={effBody} onChange={(e) => setBody(e.target.value)} />
            <div className="flex items-center gap-2">
              <Button
                onClick={() => edit.mutate()}
                disabled={edit.isPending || (!subject && !body)}
              >
                {edit.isPending ? "Saving…" : "Save changes"}
              </Button>
              <span className="text-[11px] text-slate-600">
                Protected words (non-invasive statement) stay enforced by the API.
              </span>
            </div>
          </div>
        </Card>
      )}

      <Card>
        <SectionTitle>
          {editable ? "Current draft" : "Sent content"}
        </SectionTitle>
        <pre className="whitespace-pre-wrap rounded-lg border border-[#1f2a3d] bg-[#0a0f1a] p-4 text-xs text-slate-300">
          {d.body}
        </pre>
      </Card>

      <p className="text-center text-xs text-slate-600">
        <Link href="/disclosures" className="hover:text-slate-400">
          ← Back to disclosures
        </Link>
      </p>
    </div>
  );
}
