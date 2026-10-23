"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { AppSidebar } from "@/components/nav";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const badges = useQuery({
    queryKey: ["layout-badges"],
    queryFn: async () => {
      const [nf, nt] = await Promise.all([api.findings(), api.notifications()]);
      return {
        open: nf.findings.filter((f) => f.status.startsWith("OPEN")).length,
        unread: nt.unread,
      };
    },
    refetchInterval: 60_000,
  });

  return (
    <div className="flex min-h-screen bg-[var(--bg-page)] pt-14 lg:pt-0">
      <AppSidebar
        openFindings={badges.data?.open ?? null}
        unread={badges.data?.unread ?? null}
      />
      <main className="min-w-0 flex-1">{children}</main>
    </div>
  );
}
