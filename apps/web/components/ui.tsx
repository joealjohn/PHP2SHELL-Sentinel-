"use client";

import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { useEffect, useState } from "react";
import { formatDateTime, timeAgo } from "../lib/format";

/* ── Spinner ───────────────────────────────────────────────── */
export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-slate-400">
      <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
        <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      {label}
    </span>
  );
}

/* ── Surfaces ──────────────────────────────────────────────── */
export function Card({
  children,
  className = "",
  as: Tag = "div",
}: {
  children: React.ReactNode;
  className?: string;
  as?: "div" | "section";
}) {
  return <Tag className={`card p-5 ${className}`}>{children}</Tag>;
}

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400">
      {children}
    </h2>
  );
}

/* ── Buttons ───────────────────────────────────────────────── */
const buttonStyles = {
  primary: "bg-blue-600 hover:bg-blue-500 text-white shadow-sm shadow-blue-950/40",
  secondary: "bg-[#182338] hover:bg-[#233152] text-slate-200 border border-[rgba(255,255,255,0.08)]",
  danger: "bg-red-950/60 hover:bg-red-900/70 text-red-300 border border-red-800/50",
  ghost: "bg-transparent hover:bg-[rgba(255,255,255,0.05)] text-slate-300 border border-transparent",
  success: "bg-emerald-600/90 hover:bg-emerald-500 text-white",
} as const;

export function Button({
  variant = "primary",
  size = "md",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: keyof typeof buttonStyles;
  size?: "sm" | "md";
}) {
  const pad = size === "sm" ? "px-2.5 py-1 text-xs" : "px-3 py-1.5 text-sm";
  return (
    <button
      {...props}
      className={`inline-flex items-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${pad} ${buttonStyles[variant]} ${className}`}
    />
  );
}

/* ── Form controls ─────────────────────────────────────────── */
export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`input ${props.className ?? ""}`} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`input ${props.className ?? ""}`} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea {...props} className={`input min-h-40 font-mono text-xs ${props.className ?? ""}`} />
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-slate-400">{label}</span>
      {children}
      {hint ? <span className="mt-1 block text-[11px] text-slate-500">{hint}</span> : null}
    </label>
  );
}

/* ── Badges ────────────────────────────────────────────────── */
const badgeColors = {
  CRITICAL: "bg-[var(--sev-critical-dim)] text-[var(--sev-critical)] border-[rgba(248,113,113,0.35)]",
  HIGH: "bg-[var(--sev-high-dim)] text-[var(--sev-high)] border-[rgba(251,146,60,0.35)]",
  MEDIUM: "bg-[var(--sev-medium-dim)] text-[var(--sev-medium)] border-[rgba(251,191,36,0.3)]",
  LOW: "bg-[var(--sev-low-dim)] text-[var(--sev-low)] border-[rgba(125,211,252,0.3)]",
  neutral: "bg-[var(--status-info-dim)] text-slate-300 border-[rgba(148,163,184,0.25)]",
  green: "bg-[var(--status-ok-dim)] text-[var(--status-ok)] border-[rgba(52,211,153,0.3)]",
  info: "bg-blue-500/10 text-blue-300 border-blue-500/30",
  amber: "bg-amber-500/10 text-amber-300 border-amber-500/30",
} as const;

export function Badge({
  children,
  color = "neutral",
  className = "",
}: {
  children: React.ReactNode;
  color?: keyof typeof badgeColors;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${badgeColors[color]} ${className}`}
    >
      {children}
    </span>
  );
}

export function severityColor(sev: string): keyof typeof badgeColors {
  if (sev in badgeColors) return sev as keyof typeof badgeColors;
  return "neutral";
}

/* ── Empty / error states ──────────────────────────────────── */
export function Empty({
  children,
  icon,
}: {
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[rgba(255,255,255,0.12)] p-10 text-center text-sm text-slate-500">
      {icon ? <span className="text-slate-600">{icon}</span> : null}
      <div>{children}</div>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="rounded-lg border border-red-800/50 bg-red-950/30 px-3 py-2 text-sm text-red-300"
    >
      {message}
    </div>
  );
}

/* ── Hydration-safe relative time ──────────────────────────── */
export function TimeAgo({ date, className = "" }: { date: string; className?: string }) {
  const [label, setLabel] = useState<string | null>(null);
  useEffect(() => {
    const update = () => setLabel(timeAgo(date));
    update();
    const t = setInterval(update, 30_000);
    return () => clearInterval(t);
  }, [date]);
  const absolute = new Date(
    date.endsWith("Z") || date.includes("+") ? date : `${date.replace(" ", "T")}Z`,
  ).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
  return <span className={className}>{label ?? absolute}</span>;
}

/* ── Skeleton helpers ──────────────────────────────────────── */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

/* ── Current-time stamp, rendered client-side only ─────────── */
/* Rendering `new Date()` during SSR would desync with hydration. */
export function NowStamp({ className = "" }: { className?: string }) {
  const [stamp, setStamp] = useState<string | null>(null);
  useEffect(() => setStamp(formatDateTime(new Date().toISOString())), []);
  return <span className={className}>{stamp ?? "—"}</span>;
}
