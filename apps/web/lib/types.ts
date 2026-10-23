export type Asset = {
  id: string;
  name: string;
  url: string;
  normalized_url: string;
  host: string;
  description: string | null;
  authorization_confirmed: boolean;
  authorization_confirmed_at: string | null;
  monitoring_enabled: boolean;
  scan_interval_seconds: number;
  last_scan_at: string | null;
  next_scan_at: string | null;
  open_findings: number | null;
  last_scan_status: "COMPLETED" | "FAILED" | null;
  created_at: string;
  updated_at: string;
};

export type Scan = {
  id: string;
  asset_id: string;
  status: "QUEUED" | "SCANNING" | "ANALYZING" | "COMPLETED" | "FAILED";
  scanner_version: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  summary: Record<string, unknown> | null;
  error: string | null;
  error_code: string | null;
  created_at: string;
  asset_name?: string;
};

export type Evidence = {
  id: string;
  type: string;
  name: string;
  value: string;
  source: string | null;
  confidence: string;
  collected_at: string;
};

export type Finding = {
  id: string;
  asset_id: string;
  scan_id: string;
  vulnerability_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss: number | null;
  confidence: string;
  status: string;
  state: string;
  summary: string;
  impact: string;
  remediation: string;
  detected_version: string | null;
  fixed_version: string | null;
  vendor_patch_possible: boolean | null;
  detection_method: string;
  scanner_version: string;
  references: string[] | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  created_at: string;
  asset_name?: string;
  asset_url?: string;
  evidence?: Evidence[];
  disclosures?: {
    id: string;
    status: string;
    delivery_status: string | null;
    recipient_email: string | null;
    created_at: string;
    sent_at: string | null;
  }[];
};

export type Contact = {
  id: string;
  email: string | null;
  contact_url: string | null;
  source: string;
  source_url: string | null;
  confidence: string;
  policy_url: string | null;
  encryption_url: string | null;
  preferred_languages: string | null;
  discovered_at: string;
};

export type Disclosure = {
  id: string;
  finding_id: string;
  contact_id: string | null;
  asset_id: string;
  status:
    | "DRAFT"
    | "PENDING_APPROVAL"
    | "APPROVED"
    | "SENT"
    | "DELIVERED"
    | "CANCELLED";
  delivery_status: string | null;
  subject: string;
  body: string;
  recipient_email: string | null;
  recipient_source: string | null;
  created_at: string;
  approved_at: string | null;
  sent_at: string | null;
  last_sent_at: string | null;
  error: string | null;
  finding_title?: string;
  asset_name?: string;
};

export type Notification = {
  id: string;
  type: string;
  title: string;
  message: string;
  data: Record<string, unknown> | null;
  read_at: string | null;
  created_at: string;
};

export type AuditLog = {
  id: string;
  user_id: string | null;
  asset_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
};

export type Metrics = {
  assets: number;
  open_findings: number;
  severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  resolved_findings: number;
  scan_trend: { date: string; count: number }[];
  findings_trend: { date: string; count: number }[];
  recent_scans: Scan[];
  recent_findings: Finding[];
  recent_disclosures: Disclosure[];
  recent_assets: Asset[];
};

export type ReportEntry = {
  finding_id: string;
  vulnerability_id: string;
  title: string;
  severity: Finding["severity"];
  confidence: string;
  status: string;
  asset_name: string;
  json_url: string;
  html_url: string;
};
