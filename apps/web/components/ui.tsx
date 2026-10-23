"use client";

import type { ButtonHTMLAttributes, InputHTMLAttributes, TextareaHTMLAttributes } from "react";

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

export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`card p-5 ${className}`}>{children}</div>;
}

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">{children}</h2>;
}

const buttonStyles = {
  primary: "bg-blue-600 hover:bg-blue-500 text-white",
  secondary: "bg-[#1f2a3d] hover:bg-[#2a3a55] text-slate-200",
  danger: "bg-red-900/70 hover:bg-red-800 text-red-100",
  ghost: "bg-transparent hover:bg-[#1f2a3d] text-slate-300",
} as const;

export function Button({
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: keyof typeof buttonStyles;
}) {
  return (
    <button
      {...props}
      className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${buttonStyles[variant]} ${className}`}
    />
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`input ${props.className ?? ""}`} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea {...props} className={`input min-h-40 font-mono text-xs ${props.className ?? ""}`} />
  );
}

const badgeColors = {
  CRITICAL: "bg-red-500/15 text-red-300 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-yellow-500/15 text-yellow-200 border-yellow-500/40",
  LOW: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  neutral: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  green: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
} as const;

export function Badge({
  children,
  color = "neutral",
}: {
  children: React.ReactNode;
  color?: keyof typeof badgeColors;
}) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium ${badgeColors[color]}`}
    >
      {children}
    </span>
  );
}

export function severityColor(sev: string): keyof typeof badgeColors {
  if (sev in badgeColors) return sev as keyof typeof badgeColors;
  return "neutral";
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-[#2a3a55] p-8 text-center text-sm text-slate-500">
      {children}
    </div>
  );
}
