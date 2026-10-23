"use client";

import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useLogout, useSession } from "@/hooks/use-session";
import { Spinner } from "@/components/ui";
import { AppSidebar } from "@/components/nav";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { data: user, isLoading, isError } = useSession();
  const logout = useLogout();

  const badges = useQuery({
    queryKey: ["layout-badges"],
    queryFn: async () => {
      const [nf, nt] = await Promise.all([api.findings(), api.notifications()]);
      return {
        open: nf.findings.filter((f) => f.status.startsWith("OPEN")).length,
        unread: nt.unread,
      };
    },
    enabled: !!user,
    refetchInterval: 60_000,
  });

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  }
  if (isError || !user) {
    router.replace("/login");
    return null;
  }

  const logoutNow = async () => {
    await logout.mutateAsync();
    router.replace("/login");
  };

  return (
    <div className="flex min-h-screen bg-[var(--bg-page)] pt-14 lg:pt-0">
      <AppSidebar
        email={user.email}
        openFindings={badges.data?.open ?? null}
        unread={badges.data?.unread ?? null}
        onLogout={logoutNow}
        onSignOut={logoutNow}
      />
      <main className="min-w-0 flex-1">{children}</main>
    </div>
  );
}
