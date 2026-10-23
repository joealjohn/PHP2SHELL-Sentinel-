"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Bell,
  CheckCircle2,
  FileText,
  Globe,
  LayoutDashboard,
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
import { ThemeToggle } from "./theme";

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

const RELEASE_NOTE = "Local-first · private";

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
          <div className="px-2.5 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.09em] text-ink-3">
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
                        ? "bg-accent-dim text-ink"
                        : "text-ink-2 hover:bg-raised hover:text-ink"
                    }`}
                  >
                    <item.icon
                      className={`h-4 w-4 shrink-0 ${active ? "text-accent" : "text-ink-3"}`}
                      strokeWidth={1.75}
                      aria-hidden
                    />
                    <span className="flex-1">{item.label}</span>
                    {count != null && count > 0 ? (
                      <span className="rounded-full bg-raised px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-ink-2">
                        {count > 99 ? "99+" : count}
                      </span>
                    ) : null}
                    {active ? (
                      <span className="absolute left-0 h-5 w-[2px] rounded-r bg-accent" aria-hidden />
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
  onNavigate,
}: {
  pathname: string;
  openFindings: number | null;
  unread: number | null;
  onNavigate?: () => void;
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
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-accent">
          <ShieldCheck className="h-4 w-4 text-white" aria-hidden />
        </span>
        <span>
          <span className="block text-sm font-semibold leading-4 text-ink">Sentinel</span>
          <span className="block text-[10px] leading-3 text-ink-3">{RELEASE_NOTE}</span>
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

      <div className="mx-3 mb-2 flex items-center gap-2 rounded-lg border border-line bg-raised px-3 py-2">
        <CheckCircle2 className="h-3.5 w-3.5 text-ok" strokeWidth={2} aria-hidden />
        <span className="text-xs font-medium text-ink-2">Monitor active</span>
        <span className="ml-auto h-1.5 w-1.5 rounded-full bg-ok" aria-hidden />
      </div>

      <div className="mx-3 mb-1">
        <ThemeToggle />
      </div>

      <div className="mx-3 mb-2 px-2.5">
        <span className="block min-w-0 truncate text-xs text-ink-3" title="Local single-user deployment">
          Local single-user deployment
        </span>
      </div>
      <p className="pb-3 text-center text-[10px] text-ink-3">
        Scanner v3.4.5 · DB schema up to date
      </p>
    </div>
  );
}

/* ── Full sidebar used by the app layout ───────────────────── */
export function AppSidebar({
  openFindings,
  unread,
}: {
  openFindings: number | null;
  unread: number | null;
}) {
  const pathname = usePathname();
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

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="panel hidden w-60 shrink-0 lg:block">
        <SidebarBody
          pathname={pathname}
          openFindings={openFindings}
          unread={unread}
        />
      </aside>

      {/* Mobile top bar */}
      <div className="fixed inset-x-0 top-0 z-40 flex h-14 items-center justify-between border-b border-line bg-panel px-4 lg:hidden">
        <span className="flex items-center gap-2 text-sm font-semibold text-ink">
          <ShieldCheck className="h-4 w-4 text-accent" aria-hidden /> Sentinel
        </span>
        <div className="flex items-center gap-1">
          <ThemeToggle compact />
          <button
            type="button"
            onClick={() => setOpen(true)}
            className="flex h-9 w-9 items-center justify-center rounded-lg text-ink-2 hover:bg-raised"
          >
            <span className="sr-only">Open navigation menu</span>
            <Menu className="h-5 w-5" aria-hidden />
          </button>
        </div>
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
            className={`absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col border-r border-line bg-panel shadow-2xl transition-transform duration-200 ${
              open ? "translate-x-0" : "-translate-x-full"
            }`}
          >
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="absolute right-2 top-2 flex h-9 w-9 items-center justify-center rounded-lg text-ink-2 hover:bg-raised"
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
            <div className="border-t border-line px-4 py-3">
              <ThemeToggle />
              <div className="mt-1">
                <span
                  className="block min-w-0 truncate text-xs text-ink-3"
                  title="Local single-user deployment"
                >
                  Local single-user deployment
                </span>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
