"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, SectionTitle } from "@/components/ui";
import { PageHeader } from "@/components/page";

export default function SettingsPage() {
  const badges = useQuery({
    queryKey: ["layout-badges"],
    queryFn: async () => {
      const [nf, nt] = await Promise.all([api.findings(), api.notifications()]);
      return {
        open: nf.findings.filter((f) => f.status.startsWith("OPEN")).length,
        unread: nt.unread,
      };
    },
  });

  return (
    <div className="mx-auto max-w-xl p-6">
      <PageHeader
        title="Settings"
        subtitle="Local single-user deployment — no account management is needed."
      />
      <Card className="mt-6">
        <SectionTitle>Deployment</SectionTitle>
        <dl className="mt-2 space-y-1.5 text-sm text-ink-2">
          <div className="flex justify-between gap-4">
            <dt className="text-ink-3">Mode</dt>
            <dd className="text-right">Single-user · no login</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-ink-3">Data store</dt>
            <dd className="text-right">Local Postgres (loopback only)</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-ink-3">Open findings</dt>
            <dd className="text-right tabular-nums">{badges.data?.open ?? "—"}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-ink-3">Unread notifications</dt>
            <dd className="text-right tabular-nums">{badges.data?.unread ?? "—"}</dd>
          </div>
        </dl>
      </Card>
      <Card className="mt-4">
        <SectionTitle>Scanner policy</SectionTitle>
        <p className="mt-2 text-xs text-ink-3">
          Every asset requires explicit testing authorization before scanning. Targets
          are validated and restricted to public addresses unless lab mode is explicitly
          enabled. TLS certificate verification is never bypassed.
        </p>
      </Card>
    </div>
  );
}
