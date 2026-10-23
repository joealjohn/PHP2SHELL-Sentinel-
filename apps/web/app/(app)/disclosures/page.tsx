"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { api } from "@/lib/api";
import { Card, Empty, Skeleton, Spinner, TimeAgo } from "@/components/ui";
import { PageHeader } from "@/components/page";
import { DisclosureStatusBadge, SeverityBadge } from "@/components/badges";
import { findingStatusLabelFor } from "@/lib/format";

export default function DisclosuresPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["disclosures"],
    queryFn: () => api.disclosures(),
    refetchInterval: 20_000,
  });

  const rows = data?.disclosures ?? [];

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <PageHeader
        title="Disclosures"
        subtitle="Draft → edit → test email → pending approval → approve → send. Nothing goes out without your explicit approval, and recipients come only from contacts discovered on the asset itself."
      />
      <Card className="mt-6 overflow-x-auto">
        {isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2].map((i) => <Skeleton key={i} className="h-11 w-full" />)}
          </div>
        ) : isError ? (
          <Empty>Could not load disclosures.</Empty>
        ) : rows.length === 0 ? (
          <Empty icon={<Send className="h-8 w-8" aria-hidden />}>
            Nothing here yet. Open a finding and choose &ldquo;Prepare
            disclosure&rdquo; to start the flow.
          </Empty>
        ) : (
          <table className="w-full min-w-[760px]">
            <thead>
              <tr className="border-b border-[rgba(255,255,255,0.07)]">
                <th className="th">Subject</th>
                <th className="th">Asset</th>
                <th className="th">Recipient</th>
                <th className="th">Status</th>
                <th className="th text-right">Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr
                  key={d.id}
                  className="border-b border-[rgba(255,255,255,0.04)] transition-colors last:border-0 hover:bg-[rgba(255,255,255,0.015)]"
                >
                  <td className="td max-w-[260px]">
                    <Link href={`/disclosures/${d.id}`} className="font-medium text-slate-200 hover:text-blue-300">
                      <span className="line-clamp-1">{d.subject}</span>
                    </Link>
                    <div className="truncate text-[11px] text-slate-600">{d.finding_title}</div>
                  </td>
                  <td className="td">{d.asset_name}</td>
                  <td className="td">
                    {d.recipient_email ? (
                      <span className="font-mono text-xs">{d.recipient_email}</span>
                    ) : (
                      <span className="text-slate-600">not selected</span>
                    )}
                  </td>
                  <td className="td"><DisclosureStatusBadge status={d.status} /></td>
                  <td className="td text-right text-slate-500">
                    <TimeAgo date={d.last_sent_at ?? d.sent_at ?? d.created_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <p className="mt-3 text-[11px] text-slate-600">
        {isLoading ? <Spinner label="Loading…" /> : `${rows.length} disclosure${rows.length === 1 ? "" : "s"} · language is fixed to the non-invasive template ("No exploitation was performed").`}
      </p>
    </div>
  );
}
