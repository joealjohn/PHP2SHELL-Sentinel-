"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { useLogout, useSession } from "@/hooks/use-session";
import { Spinner } from "@/components/ui";
import { useQuery } from "@tanstack/react-query";

const NAV = [
  ["Dashboard", "/dashboard"],
  ["Assets", "/assets"],
  ["Findings", "/findings"],
  ["Disclosures", "/disclosures"],
  ["Reports", "/reports"],
  ["Notifications", "/notifications"],
] as const;

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { data: user, isLoading, isError } = useSession();
  const logout = useLogout();
  const unread = useQuery({
    queryKey: ["notifications-unread"],
    queryFn: () => api.notifications(),
    select: (d) => d.unread,
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

  async function handleLogout() {
    await logout.mutateAsync();
    router.replace("/login");
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-7xl flex-col px-4">
      <header className="flex items-center gap-6 border-b border-[#1f2a3d] py-4">
        <Link href="/dashboard" className="text-lg font-bold text-white">
          🛡 Sentinel
        </Link>
        <nav className="flex flex-1 items-center gap-1 text-sm">
          {NAV.map(([label, href]) => {
            const active = pathname === href || pathname.startsWith(`${href}/`);
            return (
              <Link
                key={href}
                href={href}
                className={`rounded-lg px-3 py-1.5 transition ${
                  active
                    ? "bg-[#1f2a3d] text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {label}
                {label === "Notifications" && (unread.data ?? 0) > 0 && (
                  <span className="ml-1.5 rounded-full bg-blue-600 px-1.5 py-0.5 text-[10px] text-white">
                    {unread.data}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>
        <span className="hidden text-xs text-slate-500 sm:inline">{user.email}</span>
        <button
          onClick={handleLogout}
          className="rounded-lg border border-[#2a3a55] px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
        >
          Sign out
        </button>
      </header>
      <main className="flex-1 py-6">{children}</main>
      <footer className="border-t border-[#1f2a3d] py-4 text-[11px] text-slate-600">
        Non-invasive scanning. HIGH_CONFIDENCE is the maximum severity state a
        remote scanner can assign — never claim proof of exploitability.
      </footer>
    </div>
  );
}
