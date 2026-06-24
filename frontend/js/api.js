/**
 * Project Shield — API Client
 * All backend communication with JWT headers, retry logic, error handling.
 */
const API_BASE = "http://localhost:5000/api";

const API = {
  /** Generic fetch wrapper with auth header. */
  async _fetch(path, options = {}) {
    const token = AuthManager.getToken();
    const headers = {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
      ...(options.headers || {})
    };
    // Don't set Content-Type for FormData
    if (options.body instanceof FormData) {
      delete headers["Content-Type"];
    }

    try {
      const res = await fetch(API_BASE + path, { ...options, headers });
      if (res.status === 401) {
        AuthManager.logout();
        return null;
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Request failed" }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      console.error(`[API] ${path}:`, err.message);
      throw err;
    }
  },

  /** GET /api/health */
  async health() {
    return this._fetch("/health", { method: "GET",
      headers: {} // no auth needed
    });
  },

  /** GET /api/dashboard/stats */
  async getDashboardStats() {
    return this._fetch("/dashboard/stats");
  },

  /** POST /api/logs/upload — multipart file */
  async uploadLogFile(file) {
    const form = new FormData();
    form.append("file", file);
    return this._fetch("/logs/upload", { method: "POST", body: form });
  },

  /** GET /api/logs/analyze */
  async getLogs(page = 1, perPage = 50, label = null, severity = null) {
    let path = `/logs/analyze?page=${page}&per_page=${perPage}`;
    if (label)    path += `&label=${encodeURIComponent(label)}`;
    if (severity) path += `&severity=${encodeURIComponent(severity)}`;
    return this._fetch(path);
  },

  /** POST /api/logs/generate-demo?n=N */
  async generateDemoLogs(n = 100) {
    return this._fetch(`/logs/generate-demo?n=${n}`, { method: "POST" });
  },

  /** GET /api/threats/recent */
  async getRecentThreats() {
    return this._fetch("/threats/recent");
  },

  /** GET /api/threats/live */
  async getLiveFeed() {
    return this._fetch("/threats/live");
  },

  /** POST /api/auth/verify */
  async verify() {
    return this._fetch("/auth/verify");
  },

  /**
   * GET /api/report/generate
   * Triggers a PDF download directly in the browser via a hidden anchor tag.
   * Falls back to opening in a new tab if download doesn't work.
   */
  async generateReport() {
    const token = AuthManager.getToken();
    const res   = await fetch(API_BASE + "/report/generate", {
      method:  "GET",
      headers: { "Authorization": `Bearer ${token}` },
    });
    if (res.status === 401) { AuthManager.logout(); return; }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Report failed" }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    const contentType = res.headers.get("Content-Type") || "";
    if (contentType.includes("application/pdf")) {
      // PDF: trigger browser download
      const blob     = await res.blob();
      const pdfBlob  = new Blob([blob], { type: "application/pdf" });
      const url      = URL.createObjectURL(pdfBlob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } else {
      // JSON fallback: open in new tab
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      window.open(URL.createObjectURL(blob), "_blank");
    }
  }
};
