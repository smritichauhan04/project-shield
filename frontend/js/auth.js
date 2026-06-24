/**
 * Project Shield — Auth Manager
 * Handles JWT login, logout, token storage, and page protection.
 * NOTE: API_BASE is declared in api.js; do NOT redeclare it here.
 */
const AuthManager = {
  /**
   * Attempt login with credentials.
   * Returns true on success, false on failure.
   */
  async login(username, password) {
    try {
      const fallbackBase = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1" ? "http://localhost:5000/api" : "/api";
      const base = typeof API_BASE !== "undefined" ? API_BASE : fallbackBase;
      const res = await fetch(`${base}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      if (!res.ok) return false;
      const data = await res.json();
      if (data.access_token) {
        sessionStorage.setItem("shield_token",    data.access_token);
        sessionStorage.setItem("shield_username", data.username);
        sessionStorage.setItem("shield_role",     data.role);
        return true;
      }
      return false;
    } catch (err) {
      console.error("[Auth] Login error:", err);
      return false;
    }
  },

  /** Log out and redirect to login. */
  logout() {
    sessionStorage.clear();
    window.location.href = "index.html";
  },

  /** Get stored token. */
  getToken() {
    return sessionStorage.getItem("shield_token");
  },

  /** Get stored username. */
  getUsername() {
    return sessionStorage.getItem("shield_username") || "User";
  },

  /** Get stored role. */
  getRole() {
    return sessionStorage.getItem("shield_role") || "Analyst";
  },

  /** Check if user is authenticated; redirect if not. */
  requireAuth() {
    const token = this.getToken();
    if (!token) {
      window.location.href = "index.html";
      return false;
    }
    return true;
  },

  /** Build Authorization header. */
  authHeader() {
    return { "Authorization": `Bearer ${this.getToken()}` };
  }
};

// Auto-protect the page if this is dashboard
if (
  typeof window !== "undefined" &&
  window.location.pathname.includes("dashboard")
) {
  AuthManager.requireAuth();
}
