import type { Disclosure, Finding } from "./types";

export function timeAgo(dateStr: string): string {
  const then = new Date(dateStr.endsWith("Z") || dateStr.includes("+")
    ? dateStr
    : `${dateStr.replace(" ", "T")}Z`).getTime();
  if (Number.isNaN(then)) return dateStr;
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 45) return "just now";
  if (s < 90) return "1 min ago";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return `${Math.floor(d / 30)}mo ago`;
}

export function formatDateTime(dateStr: string): string {
  return new Date(dateStr.endsWith("Z") || dateStr.includes("+")
    ? dateStr
    : `${dateStr.replace(" ", "T")}Z`).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export type Severity = Finding["severity"];

export const severityLabel: Record<string, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

export const scanStatusLabel: Record<string, string> = {
  QUEUED: "Queued",
  SCANNING: "Scanning",
  ANALYZING: "Analyzing",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

export const findingStatusLabel: Record<string, string> = {
  OPEN: "Open",
  OPEN_RISK_ACCEPTED: "Open (risk accepted)",
  OPEN_TRACKED: "Open (tracked upstream)",
  RESOLVED_PATCHED: "Resolved (patched)",
  RESOLVED_FIXED: "Resolved (fixed)",
  RESOLVED_WONT_FIX: "Resolved (won't fix)",
  RESOLVED_FALSE_POSITIVE: "False positive",
};

export function findingStatusLabelFor(status: string): string {
  return findingStatusLabel[status] ?? status.replaceAll("_", " ").toLowerCase();
}

export const disclosureStatusLabel: Record<string, string> = {
  DRAFT: "Draft",
  PENDING_APPROVAL: "Pending approval",
  APPROVED: "Approved",
  SENT: "Sent",
  DELIVERED: "Delivered",
  CANCELLED: "Cancelled",
};

export const notificationTypeLabel: Record<string, string> = {
  SCAN_COMPLETED: "Scan completed",
  SCAN_FAILED: "Scan failed",
  FINDING_OPENED: "New finding",
  FINDING_RESOLVED: "Finding resolved",
  DISCLOSURE_SENT: "Disclosure sent",
  DISCLOSURE_DELIVERED: "Disclosure delivered",
  DISCLOSURE_FAILED: "Disclosure failed",
};

export function contactLabelFor(x: { email: string | null; contact_url: string | null }): string {
  return x.email ?? x.contact_url ?? "(unknown)";
}

export function isResolved(f: Finding): boolean {
  return f.status.startsWith("RESOLVED");
}

/**
 * Turns raw scanner/network errors into plain guidance. Verification is
 * never bypassed, so TLS failures must be worded honestly and fixably.
 */
export function friendlyScanError(msg: string | null | undefined): string {
  if (!msg) return "Unknown error";
  const s = msg;
  if (s.includes("CERTIFICATE_VERIFY_FAILED") || s.includes("certificate verify failed")) {
    if (s.includes("Hostname mismatch") || s.includes("doesn't match")) {
      return "TLS certificate doesn't match this host — the server serves a certificate that doesn't cover the URL (check www vs non-www address).";
    }
    return "TLS certificate chain could not be verified (server likely omits intermediate certificates) — Sentinel never bypasses certificate verification.";
  }
  if (s.includes("ConnectError")) return "Could not connect to the target — host unreachable, refused, or DNS failure.";
  return s;
}

export function disclosureStateIcon(d: Disclosure): string {
  if (d.status === "CANCELLED") return "Cancelled";
  if (d.delivery_status === "FAILED") return "Delivery failed";
  if (d.error) return "Error";
  return "";
}
