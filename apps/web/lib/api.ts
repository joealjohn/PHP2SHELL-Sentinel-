import type {
  Asset,
  AuditLog,
  Contact,
  Disclosure,
  Finding,
  Metrics,
  Notification,
  ReportEntry,
  Scan,
} from "./types";

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const err =
      (data as { error?: { code?: string; message?: string } } | null)?.error ??
      {};
    throw new ApiError(
      res.status,
      err.code ?? "ERROR",
      err.message ?? `Request failed (${res.status}).`,
    );
  }
  return data as T;
}

export const api = {
  /* health (public) */
  requestPublic: <T,>(method: "GET", path: string) => request<T>(method, path),

  /* metrics */
  metrics: () => request<Metrics>("GET", "/api/metrics/summary"),

  /* assets */
  assets: () => request<{ assets: Asset[] }>("GET", "/api/assets"),
  asset: (id: string) => request<Asset>("GET", `/api/assets/${id}`),
  createAsset: (payload: {
    name: string;
    url: string;
    description?: string;
    scan_interval_seconds?: number;
    monitoring_enabled?: boolean;
    authorization_confirmed?: boolean;
  }) => request<Asset>("POST", "/api/assets", payload),
  updateAsset: (
    id: string,
    payload: {
      name?: string;
      description?: string;
      scan_interval_seconds?: number;
      monitoring_enabled?: boolean;
      authorization_confirmed?: boolean;
    },
  ) => request<Asset>("PATCH", `/api/assets/${id}`, payload),
  deleteAsset: (id: string) =>
    request<{ ok: boolean }>("DELETE", `/api/assets/${id}`),
  queueScan: (id: string) =>
    request<{ scan_id: string; status: string }>(
      "POST",
      `/api/assets/${id}/scan`,
    ),
  assetScans: (id: string) =>
    request<{ scans: Scan[] }>("GET", `/api/assets/${id}/scans`),

  /* contacts */
  contacts: (assetId: string) =>
    request<{ contacts: Contact[] }>(
      "GET",
      `/api/assets/${assetId}/contacts`,
    ),
  discoverContacts: (assetId: string) =>
    request<{ task_id: string; status: string }>(
      "POST",
      `/api/assets/${assetId}/contacts/discover`,
    ),

  /* scans */
  scans: (assetId?: string, limit?: number) => {
    const q = new URLSearchParams();
    if (assetId) q.set("asset_id", assetId);
    if (limit) q.set("limit", String(limit));
    const s = q.toString();
    return request<{ scans: Scan[] }>("GET", `/api/scans${s ? `?${s}` : ""}`);
  },
  scan: (id: string) => request<Scan>("GET", `/api/scans/${id}`),
  cancelScan: (id: string) =>
    request<Scan>("POST", `/api/scans/${id}/cancel`),
  scanFindings: (id: string) =>
    request<{ findings: Finding[] }>("GET", `/api/scan/${id}/findings`),

  /* findings */
  findings: (params: {
    severity?: string;
    asset_id?: string;
    status?: string;
    vuln?: string;
    limit?: number;
  } = {}) => {
    const q = new URLSearchParams();
    if (params.severity) q.set("severity", params.severity);
    if (params.asset_id) q.set("asset_id", params.asset_id);
    if (params.status) q.set("status", params.status);
    if (params.vuln) q.set("vuln", params.vuln);
    if (params.limit) q.set("limit", String(params.limit));
    const s = q.toString();
    return request<{ findings: Finding[] }>(
      "GET",
      `/api/findings${s ? `?${s}` : ""}`,
    );
  },
  finding: (id: string) => request<Finding>("GET", `/api/findings/${id}`),
  rescanFinding: (id: string) =>
    request<{ scan_id: string }>("POST", `/api/findings/${id}/rescan`),
  closeFinding: (id: string) =>
    request<{ status: string }>("POST", `/api/findings/${id}/close`),

  /* disclosures */
  disclosures: () =>
    request<{ disclosures: Disclosure[] }>("GET", "/api/disclosures"),
  disclosure: (id: string) =>
    request<Disclosure>(
      "GET",
      `/api/disclosures/${id}`,
    ),
  draftDisclosure: (findingId: string) =>
    request<Disclosure>(
      "POST",
      `/api/findings/${findingId}/disclosure`,
    ),
  editDisclosure: (
    id: string,
    payload: { subject: string; body: string },
  ) => request<Disclosure>("PATCH", `/api/disclosures/${id}`, payload),
  markPending: (id: string) =>
    request<Disclosure>("POST", `/api/disclosures/${id}/mark-pending`),
  testEmail: (id: string) =>
    request<{ ok: boolean; sent_to: string; when: string }>(
      "POST",
      `/api/disclosures/${id}/test-email`,
    ),
  approve: (id: string) =>
    request<Disclosure>("POST", `/api/disclosures/${id}/approve`),
  sendNow: (id: string) =>
    request<Disclosure>("POST", `/api/disclosures/${id}/send-now`),
  cancelDisclosure: (id: string) =>
    request<Disclosure>("POST", `/api/disclosures/${id}/cancel`),

  /* reports */
  reports: () =>
    request<{
      reports: ReportEntry[];
    }>("GET", "/api/reports"),

  /* notifications */
  notifications: () =>
    request<{ notifications: Notification[]; unread: number }>(
      "GET",
      "/api/notifications",
    ),
  markRead: (id: string) =>
    request<{ ok: boolean }>(
      "POST",
      `/api/notifications/${id}/read`,
    ),
  markAllRead: () =>
    request<{ ok: boolean }>(
      "POST",
      "/api/notifications/read-all",
    ),

  /* audit */
  audit: () =>
    request<{ audit_logs: AuditLog[] }>(
      "GET",
      "/api/audit",
    ),
};
