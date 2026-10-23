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
  User,
} from "./types";

const CSRF_COOKIE = "sentinel_csrf";

export class ApiError extends Error {
  code: string;
  status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function csrfToken(): string | null {
  const match = document.cookie
    .split("; ")
    .find((c) => c.startsWith(`${CSRF_COOKIE}=`));
  return match ? decodeURIComponent(match.split("=")[1]) : null;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  const mutating = !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
  if (body !== undefined) headers.set("Content-Type", "application/json");
  if (mutating) {
    const token = csrfToken();
    if (token) headers.set("x-csrf-token", token);
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
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
  /* auth */
  register: (email: string, password: string) =>
    request<User>("POST", "/api/auth/register", { email, password }),
  login: (email: string, password: string) =>
    request<User>("POST", "/api/auth/login", { email, password }),
  me: () => request<User>("GET", "/api/auth/me"),
  logout: () => request<{ ok: boolean }>("POST", "/api/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    request<{ ok: boolean }>("POST", "/api/auth/change-password", {
      current_password,
      new_password,
    }),

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
  scans: (assetId?: string) => {
    const q = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : "";
    return request<{ scans: Scan[] }>("GET", `/api/scans${q}`);
  },
  scan: (id: string) => request<Scan>("GET", `/api/scans/${id}`),
  cancelScan: (id: string) =>
    request<Scan>("POST", `/api/scans/${id}/cancel`),
  scanFindings: (id: string) =>
    request<{ findings: Finding[] }>("GET", `/api/scan/${id}/findings`),

  /* findings */
  findings: (params: { severity?: string; asset_id?: string } = {}) => {
    const q = new URLSearchParams();
    if (params.severity) q.set("severity", params.severity);
    if (params.asset_id) q.set("asset_id", params.asset_id);
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
