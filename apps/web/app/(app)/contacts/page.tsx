"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Search, UserRoundPlus, Users } from "lucide-react";
import { api } from "@/lib/api";
import type { Contact } from "@/lib/types";
import { Badge, Card, Empty, Select, Skeleton } from "@/components/ui";
import { PageHeader, SectionHeader } from "@/components/page";
import { formatDateTime } from "@/lib/format";

function sourceLabel(s: string): string {
  return {
    SECURITY_TXT: "security.txt",
    meta: "page meta tag",
    page_link: "page link",
  }[s] ?? s.replaceAll("_", " ").toLowerCase();
}

const ALL_ASSETS = "__all__";

export default function ContactsPage() {
  const [assetId, setAssetId] = useState(ALL_ASSETS);
  const [query, setQuery] = useState("");
  const assets = useQuery({ queryKey: ["assets"], queryFn: () => api.assets() });

  const assetsList = assets.data?.assets ?? [];

  const rows = useQuery({
    queryKey: ["contacts-aggregate", assetsList.map((a) => a.id).join("|"), assetId],
    queryFn: async () => {
      const targets = assetId === ALL_ASSETS ? assetsList : assetsList.filter((a) => a.id === assetId);
      const out: { asset: { id: string; name: string; host: string }; contact: Contact }[] = [];
      const results = await Promise.all(
        targets.map((a) => api.contacts(a.id).catch(() => ({ contacts: [] }))),
      );
      for (const [i, a] of targets.entries()) {
        for (const c of results[i].contacts) out.push({ asset: a, contact: c });
      }
      return out;
    },
    enabled: assets.isSuccess,
  });

  const filtered = (rows.data ?? []).filter(
    (r) =>
      !query ||
      (r.contact.email ?? "").toLowerCase().includes(query.toLowerCase()) ||
      (r.contact.contact_url ?? "").toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="mx-auto max-w-[1100px] p-6">
      <PageHeader
        title="Contacts"
        subtitle="Humans to notify when something is found — gathered non-invasively from security.txt and page metadata. Disclosure can only use these."
      />

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" aria-hidden />
          <input
            aria-label="Search contacts"
            className="input w-64 pl-8"
            placeholder="Search contacts…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </span>
        <Select
          aria-label="Filter by asset"
          className="w-52"
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
        >
          <option value={ALL_ASSETS}>All assets</option>
          {assetsList.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </Select>
      </div>

      <Card className="mt-4 overflow-x-auto">
        <SectionHeader
          title={`${filtered.length} contact${filtered.length === 1 ? "" : "s"}`}
        />
        {assets.isLoading || rows.isLoading ? (
          <div className="flex flex-col gap-3 p-1">
            {[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        ) : filtered.length === 0 ? (
          <Empty icon={<Users className="h-8 w-8" aria-hidden />}>
            No contacts. Open an asset and press &ldquo;Discover contacts&rdquo; —
            discovery reads public disclosure channels only.
          </Empty>
        ) : (
          <table className="w-full min-w-[720px]">
            <thead>
              <tr className="border-b border-[rgba(255,255,255,0.07)]">
                <th className="th">Contact</th>
                <th className="th">Asset</th>
                <th className="th">Source</th>
                <th className="th">Confidence</th>
                <th className="th text-right">Discovered</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr
                  key={r.contact.id}
                  className="border-b border-[rgba(255,255,255,0.04)] transition-colors last:border-0 hover:bg-[rgba(255,255,255,0.015)]"
                >
                  <td className="td">
                    <span className="font-mono text-xs text-slate-200">
                      {r.contact.email ?? r.contact.contact_url}
                    </span>
                    {r.contact.encryption_url ? (
                      <div className="text-[10px] text-slate-600">encryption key published</div>
                    ) : null}
                  </td>
                  <td className="td">
                    <Link href={`/assets/${r.asset.id}`} className="hover:text-slate-200">
                      {r.asset.name}
                    </Link>
                  </td>
                  <td className="td">{sourceLabel(r.contact.source)}</td>
                  <td className="td">
                    <Badge color={r.contact.confidence === "HIGH" ? "green" : "neutral"}>
                      {r.contact.confidence}
                    </Badge>
                  </td>
                  <td className="td text-right text-slate-500">{formatDateTime(r.contact.discovered_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <p className="mt-3 flex items-start gap-2 text-[11px] text-slate-600">
        <UserRoundPlus className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
        Contacts come from /.well-known/security.txt, meta tags, and visible
        mailto links only — the S3 disclosure-safety rule requires the
        test-email-first flow before any real send.
      </p>
    </div>
  );
}
