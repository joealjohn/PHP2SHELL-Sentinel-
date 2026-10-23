"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Bell,
  CheckCircle2,
  FileText,
  Globe,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Send,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { api } from "../lib/api";

type NavItem = {
  label: string;
  href: string;
  icon: typeof LayoutDashboard;
  badge?: "open" | "unread";
};

type NavGroup = { heading: string; items: NavItem[] };

const NAV: NavGroup[] = [
  {
    heading: "Overview",
    items: [{ label: "Dashboard", href: "/dashboard", icon: LayoutDashboard }],
  },
  {
    heading: "Monitoring",
    items: [
      { label: "Assets", href: "/assets", icon: Globe },
      { label: "Scans", href: "/scans", icon: Radar },
    ],
  },
  {
    heading: "Security",
    items: [
      { label: "Findings", href: "/findings", icon: ShieldAlert },
      { label: "Vulnerabilities", href: "/vulnerabilities", icon: ShieldCheck },
    ],
  },
  {
    heading: "Disclosure",
    items: [
      { label: "Contacts", href: "/contacts", icon: Users },
      { label: "Disclosures", href: "/disclosures", icon: Send },
      { label: "Reports", href: "/reports", icon: FileText },
    ],
  },
  {
    heading: "System",
    items: [
      { label: "Notifications", href: "/notifications", icon: Bell, badge: "unread" },
      { label: "Audit log", href: "/audit", icon: ScrollText },
    ],
  },
];

const RELEASE_NOTE = "Local-first · no data leaves this machine";

function isActive(pathname: string, href: string): boolean {
  if (pathname === href) return true;
  return href !== "/assets" && pathname.startsWith(`${href}/`);
}

function NavList({
  pathname,
  openFindings,
  unread,
  onNavigate,
}: {
  pathname: string;
  openFindings: number | null;
  unread: number | null;
  onNavigate?: () => void;
}) {
  return (
    <nav aria-label="Primary" className="flex flex-col gap-5 px-3 py-4">
      {NAV.map((group) => (
        <div key={group.heading}>
          <div className="px-2.5 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.09em] text-slate-600">
            {group.heading}
          </div>
          <ul className="flex flex-col gap-0.5">
            {group.items.map((item) => {
              const active = isActive(pathname, item.href);
              const count =
                item.badge === "open" ? openFindings : item.badge === "unread" ? unread : null;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={`flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] font-medium transition-colors ${
                      active
                        ? "bg-[#132038] text-slate-100"
                        : "text-slate-400 hover:bg-[rgba(255,255,255,0.04)] hover:text-slate-200"
                    }`}
                  >
                    <item.icon
                      className={`h-4 w-4 shrink-0 ${active ? "text-blue-400" : ""}`}
                      strokeWidth={1.75}
                      aria-hidden
                    />
                    <span className="flex-1">{item.label}</span>
                    {count != null && count > 0 ? (
                      <span className="rounded-full bg-[rgba(255,255,255,0.07)] px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-slate-300">
                        {count > 99 ? "99+" : count}
                      </span>
                    ) : null}
                    {active ? (
                      <span className="absolute left-0 h-5 w-[2px] rounded-r bg-blue-500" aria-hidden />
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function SidebarBody({
  pathname,
  openFindings,
  unread,
  onLogout,
  onNavigate,
  email,
}: {
  pathname: string;
  openFindings: number | null;
  unread: number | null;
  onLogout: () => void;
  onNavigate?: () => void;
  email: string;
}) {
  const [healthy, setHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    let dead = false;
    const check = () => {
      api
        .requestPublic("GET", "/api/health")
        .then(() => !dead && setHealthy(true))
        .catch(() => !dead && setHealthy(false));
    };
    check();
    const t = setInterval(check, 30_000);
    return () => {
      dead = true;
      clearInterval(t);
    };
  }, []);

  return (
    <div className="flex h-full flex-col">
      <Link href="/dashboard" onClick={onNavigate} className="flex items-center gap-2.5 px-5 pb-4 pt-5">
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-600">
          <ShieldCheck className="h-4 w-4 text-white" aria-hidden />
        </span>
        <span>
          <span className="block text-sm font-semibold leading-4 text-slate-100">Sentinel</span>
          <span className="block text-[10px] leading-3 text-slate-500">{RELEASE_NOTE}</span>
        </span>
      </Link>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <NavList
          pathname={pathname}
          openFindings={openFindings}
          unread={unread}
          onNavigate={onNavigate}
        />
      </div>

      <div className="mx-3 mb-2 rounded-lg border border-[rgba(255,255,255,0.07)] bg-[rgba(255,255,255,0.02)] px-3 py-2.5">
        <div className="flex items-center gap-2 text-xs">
          <CheckCircle2
            className="h-3.5 w-3.5 text-[var(--status-ok)]"
            strokeWidth={2}
            aria-hidden
          />
          <span className="font-medium text-slate-300">Monitor active</span>
          <span className="text-[var(--status-ok)]" style={{ fontSize: 10 }}>
            ●
          </span>
        </div>
      </div>

      <div className="mx-3 mb-2 rounded-lg px-3 py-2">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-xs text-slate-400" title={email}>
            {email}
          </span>
          <button
            type="button"
            onClick={onLogout}
            aria-label="Log out"
            className="flex items-center gap-1 rounded-md px-2 py-1 text-[11px] text-slate-500 transition-colors hover:bg-[rgba(255,255,255,0.05)] hover:text-red-300"
          >
            <LogOut className="h-3 w-3" aria-hidden /> Log out
          </button>
        </div>
      </div>
      <p className="pb-3 text-center text-[10px] text-slate-600">
        Scanner v3.4.5 · DB schema up to date
      </p>
    </div>
  );
}

/* ── Full sidebar used by the app layout ───────────────────── */
export function AppSidebar({
  email,
  openFindings,
  unread,
  onLogout,
  onSignOut,
}: {
  email: string;
  openFindings: number | null;
  unread: number | null;
  onLogout: () => void;
  onSignOut: () => void;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const logout = () => {
    setOpen(false);
    onLogout();
    router.push("/login");
    router.refresh();
  };

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="panel hidden w-60 shrink-0 lg:block">
        <SidebarBody
          pathname={pathname}
          openFindings={openFindings}
          unread={unread}
          email={email}
          onLogout={logout}
        />
      </aside>

      {/* Mobile top bar */}
      <div className="fixed inset-x-0 top-0 z-40 flex h-14 items-center justify-between border-b border-[rgba(255,255,255,0.07)] bg-[var(--bg-panel)] px-4 lg:hidden">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <ShieldCheck className="h-4 w-4 text-blue-500" aria-hidden /> Sentinel
        </span>
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-300 hover:bg-[rgba(255,255,255,0.06)]"
        >
          <span className="sr-only">Open navigation menu</span>
          <Menu className="h-5 w-5" aria-hidden />
        </button>
      </div>

      {/* Mobile drawer */}
      {mounted && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Primary navigation"
          className={`fixed inset-0 z-50 lg:hidden ${open ? "" : "pointer-events-none"}`}
        >
          <div
            className={`absolute inset-0 bg-black/60 transition-opacity duration-200 ${
              open ? "opacity-100" : "opacity-0"
            }`}
            onClick={() => setOpen(false)}
            aria-hidden
          />
          <div
            className={`absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col bg-[var(--bg-panel)] shadow-2xl transition-transform duration-200 ${
              open ? "translate-x-0" : "-translate-x-full"
            }`}
          >
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="absolute right-2 top-2 flex h-9 w-9 items-center justify-center rounded-lg text-slate-400 hover:bg-[rgba(255,255,255,0.06)]"
            >
              <span className="sr-only">Close navigation menu</span>
              <X className="h-5 w-5" aria-hidden />
            </button>
            <div className="min-h-0 flex-1 overflow-y-auto">
              <NavList
                pathname={pathname}
                openFindings={openFindings}
                unread={unread}
                onNavigate={() => setOpen(false)}
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}
