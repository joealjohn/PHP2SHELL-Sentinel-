import { Badge, severityColor } from "./ui";
import {
  disclosureStatusLabel,
  findingStatusLabelFor,
  scanStatusLabel,
  severityLabel,
} from "../lib/format";

export function SeverityBadge({ severity }: { severity: string }) {
  const label = severityLabel[severity] ?? severity;
  const dot =
    severity === "CRITICAL"
      ? "bg-crit"
      : severity === "HIGH"
        ? "bg-high"
        : severity === "MEDIUM"
          ? "bg-med"
          : "bg-low";
  return (
    <Badge color={severityColor(severity)}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} aria-hidden />
      {label}
    </Badge>
  );
}

const scanStatusColor: Record<string, "neutral" | "green" | "amber" | "info" | "CRITICAL"> = {
  COMPLETED: "green",
  FAILED: "CRITICAL",
  QUEUED: "neutral",
  SCANNING: "info",
  ANALYZING: "info",
};

export function ScanStatusBadge({ status }: { status: string }) {
  const color =
    scanStatusColor[status] ?? "neutral";
  return <Badge color={color}>{scanStatusLabel[status] ?? status}</Badge>;
}

const findingStatusColor: Record<string, "neutral" | "green" | "amber" | "CRITICAL"> = {
  OPEN: "CRITICAL",
  OPEN_RISK_ACCEPTED: "amber",
  OPEN_TRACKED: "amber",
  RESOLVED_PATCHED: "green",
  RESOLVED_FIXED: "green",
  RESOLVED_WONT_FIX: "neutral",
  RESOLVED_FALSE_POSITIVE: "neutral",
};

export function FindingStatusBadge({ status }: { status: string }) {
  const color = findingStatusColor[status] ?? "neutral";
  return <Badge color={color}>{findingStatusLabelFor(status)}</Badge>;
}

export function InconclusiveBadge({
  label = "Inconclusive",
}: {
  label?: string;
}) {
  return (
    <Badge color="amber">
      <span className="h-1.5 w-1.5 rounded-full bg-med" aria-hidden />
      {label}
    </Badge>
  );
}

const disclosureColor: Record<string, "neutral" | "green" | "amber" | "info" | "CRITICAL"> = {
  DRAFT: "neutral",
  PENDING_APPROVAL: "amber",
  APPROVED: "info",
  SENT: "info",
  DELIVERED: "green",
  CANCELLED: "neutral",
};

export function DisclosureStatusBadge({ status }: { status: string }) {
  const color = disclosureColor[status] ?? "neutral";
  return <Badge color={color}>{disclosureStatusLabel[status] ?? status}</Badge>;
}
