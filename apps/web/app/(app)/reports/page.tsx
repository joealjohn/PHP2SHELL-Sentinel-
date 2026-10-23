"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { FileDown, FileText, FileJson2, Printer } from "lucide-react";
import { api } from "@/lib/api";
import { Badge, Card, Empty, ErrorBanner, Skeleton, Spinner, severityColor } from "@/components/ui";
import { PageHeader } from "@/components/page";
import { formatDateTime } from "@/lib/format";

/**
 * Renders the (same-origin) HTML report in a hidden iframe and opens the
 * browser's print dialog — "Save as PDF" needs zero extra dependencies and
 * keeps the document byte-identical to the server-rendered report.
 */
function printAsPdf(url: string, title: string) {
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.style.position = "fixed";
  frame.style.right = "0";
  frame.style.bottom = "0";
  frame.style.width = "0";
  frame.style.height = "0";
  frame.style.border = "0";
  frame.title = title;
  document.body.appendChild(frame);
  fetch(url)
    .then((r) => {
      if (!r.ok) throw new Error(`Report fetch failed (${r.status})`);
      return r.text();
    })
    .then((html) => {
      frame.srcdoc = html;
      frame.onload = () => {
        const win = frame.contentWindow;
        if (win) {
          win.focus();
          win.print();
        }
        setTimeout(() => frame.remove(), 60_000);
      };
    })
    .catch(() => {
      frame.remove();
      alert("Could not load the report for printing — try the HTML link instead.");
    });
}

export default function ReportsPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.reports(),
    refetchInterval: 60_000,
  });

  const rows = data?.reports ?? [];

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <PageHeader
        title="Reports"
        subtitle="Shareable, non-exploitative reports — machine-readable JSON for trackers and a human-readable HTML document, every one stating plainly that no exploitation was performed."
      />
      <Card className="mt-6">
        {isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2].map((i) => <Skeleton key={i} className="h-11 w-full" />)}
          </div>
        ) : isError ? (
          <ErrorBanner message="Could not load reports." />
        ) : rows.length === 0 ? (
          <Empty icon={<FileText className="h-8 w-8" aria-hidden />}>
            Reports appear here once findings exist.
          </Empty>
        ) : (
          <ul className="divide-y divide-[rgba(255,255,255,0.06)]">
            {rows.map((r) => (
              <li
                key={r.finding_id}
                className="flex flex-wrap items-center justify-between gap-3 py-3"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge color={severityColor(r.severity)}>
                      {r.severity === "CRITICAL" ? "Critical" : r.severity[0] + r.severity.slice(1).toLowerCase()}
                    </Badge>
                    <Link href={`/findings/${r.finding_id}`} className="truncate text-sm font-medium text-slate-200 hover:text-blue-300">
                      {r.title}
                    </Link>
                  </div>
                  <div className="truncate text-xs text-slate-600">
                    {r.vulnerability_id} · {r.asset_name} · {r.status.startsWith("RESOLVED") ? "resolved" : "open"} · {r.confidence} confidence
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2 text-xs">
                  {/* API returns /reports/... without /api prefix */}
                  <button
                    type="button"
                    className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-2.5 py-1 font-medium text-white transition-colors hover:bg-blue-500"
                    onClick={() => printAsPdf(`/api${r.html_url}`, `${r.vulnerability_id} — ${r.title}`)}
                  >
                    <Printer className="h-3.5 w-3.5" aria-hidden /> PDF
                  </button>
                  <a className="inline-flex items-center gap-1.5 rounded-lg border border-[rgba(255,255,255,0.1)] px-2.5 py-1 text-slate-300 transition-colors hover:bg-[rgba(255,255,255,0.05)]" href={`/api${r.html_url}`} download>
                    <FileDown className="h-3.5 w-3.5" aria-hidden /> HTML
                  </a>
                  <a className="inline-flex items-center gap-1.5 rounded-lg border border-[rgba(255,255,255,0.1)] px-2.5 py-1 text-slate-300 transition-colors hover:bg-[rgba(255,255,255,0.05)]" href={`/api${r.json_url}`}>
                    <FileJson2 className="h-3.5 w-3.5" aria-hidden /> JSON
                  </a>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <p className="mt-3 text-[11px] text-slate-600">
        {isLoading ? <Spinner label="Loading…" /> : `${rows.length} report${rows.length === 1 ? "" : "s"} · generated ${formatDateTime(new Date().toISOString())}`}
      </p>
    </div>
  );
}
