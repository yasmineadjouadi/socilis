const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function authHeaders() {
  const token = localStorage.getItem("access_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...options.headers,
    },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "API error");
  }
  return res.json();
}

async function download(path, filename) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error("Download failed");
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Auth ──────────────────────────────────────────────────────
export const authApi = {
  login: async (credentials) => {
    const data = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
    localStorage.setItem("access_token", data.access_token);
    localStorage.setItem("role", data.role);
    return data;
  },

  logout: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("role");
  },

  me: () => request("/auth/me"),

  updateProfile: (data) =>
    request("/auth/me", { method: "PUT", body: JSON.stringify(data) }),

  changePassword: (old_password, new_password) =>
    request("/auth/change-password", {
      method: "PUT",
      body: JSON.stringify({ old_password, new_password }),
    }),

  listUsers: () => request("/auth/users"),

  createUser: (email, password) =>
    request("/auth/create-user", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  toggleUser: (user_id) =>
    request(`/auth/toggle-user/${user_id}`, { method: "PUT" }),

  deleteUser: (user_id) =>
    request(`/auth/delete-user/${user_id}`, { method: "DELETE" }),

  resetPassword: (user_id) =>
    request("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ user_id }),
    }),

  getLogs: (limit = 100) => request(`/auth/logs?limit=${limit}`),

  updateNgrokUrl: (llm_api_url) =>
    request("/auth/ngrok-url", {
      method: "PUT",
      body: JSON.stringify({ llm_api_url }),
    }),

  forgotPassword: (email) =>
    request("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  getResetRequests: () => request("/auth/reset-requests"),

  approveReset: (request_id, new_password) =>
    request(`/auth/approve-reset/${request_id}`, {
      method: "POST",
      body: JSON.stringify({ new_password }),
    }),

  rejectReset: (request_id) =>
    request(`/auth/reject-reset/${request_id}`, { method: "POST" }),
};

// ── IOC enrichment direct ─────────────────────────────────────
export const hashApi = {
  analyze: (hash) => request(`/hash/?param=${encodeURIComponent(hash)}`),
};

export const ipApi = {
  analyze: (ip) => request(`/ip/?param=${encodeURIComponent(ip)}`),
};

export const domainApi = {
  analyze: (domain) => request(`/domain/?param=${encodeURIComponent(domain)}`),
};

export const urlApi = {
  analyze: (url) => request(`/url/?param=${encodeURIComponent(url)}`),
};

export const mailApi = {
  analyze: (email) => request(`/mail/?email=${encodeURIComponent(email)}`),
};

export const cveApi = {
  analyze: (cve_id) => request(`/cve/?cve_id=${encodeURIComponent(cve_id)}`),
};

// ── IOC analyze ───────────────────────────────────────────────
export const iocApi = {
  analyze: (indicator, force_rag = false) =>
    request(`/ioc/analyze?force_rag=${force_rag}`, {
      method: "POST",
      body: JSON.stringify({ indicator }),
    }),

  bulk: (indicators, force_rag = false) =>
    request("/ioc/bulk", {
      method: "POST",
      body: JSON.stringify({ indicators, force_rag }),
    }),
};

// ── Chatbot ───────────────────────────────────────────────────
export const chatbotApi = {
  message: (message, session_id = null, model) =>
    request("/chatbot/message", {
      method: "POST",
      body: JSON.stringify({ message, session_id, model }),
    }),

  bulk: (indicators, session_id = null, model) =>
    request("/chatbot/analyze/bulk", {
      method: "POST",
      body: JSON.stringify({ indicators, session_id, model }),
    }),
};

// ── Chat sessions ─────────────────────────────────────────────
export const chatSessionsApi = {
  create: (title = "Nouvelle conversation") =>
    request("/chat/sessions", {
      method: "POST",
      body: JSON.stringify({ title }),
    }),

  list: () => request("/chat/sessions"),

  delete: (session_id) =>
    request(`/chat/sessions/${session_id}`, { method: "DELETE" }),

  rename: (session_id, title) =>
    request(`/chat/sessions/${session_id}`, {
      method: "PUT",
      body: JSON.stringify({ title }),
    }),

  getMessages: (session_id) =>
    request(`/chat/sessions/${session_id}/messages`),

  addMessage: (session_id, message) =>
    request(`/chat/sessions/${session_id}/messages`, {
      method: "POST",
      body: JSON.stringify({ session_id, message }),
    }),
};

// ── History ───────────────────────────────────────────────────
export const historyApi = {
  get: ({ limit = 50, offset = 0, ioc_type = null, risk_level = null } = {}) => {
    const params = new URLSearchParams({ limit, offset });
    if (ioc_type)   params.append("ioc_type", ioc_type);
    if (risk_level) params.append("risk_level", risk_level);
    return request(`/history/?${params}`);
  },

  getFavorites: () => request("/history/favorites"),

  search: (q) => request(`/history/search?q=${encodeURIComponent(q)}`),

  toggleFavorite: (scan_id) =>
    request(`/history/${scan_id}/favorite`, { method: "PUT" }),

  delete: (scan_id) =>
    request(`/history/${scan_id}`, { method: "DELETE" }),
};

// ── Stats ─────────────────────────────────────────────────────
export const statsApi = {
  get: ({ ioc_type = null, date_from = null, date_to = null } = {}) => {
    const params = new URLSearchParams();
    if (ioc_type)  params.append("ioc_type", ioc_type);
    if (date_from) params.append("date_from", date_from);
    if (date_to)   params.append("date_to", date_to);
    const qs = params.toString();
    return request(`/stats/${qs ? "?" + qs : ""}`);
  },
};

// ── Export ────────────────────────────────────────────────────
export const exportApi = {
  csv: ({ ioc_type, risk_level } = {}) => {
    const params = new URLSearchParams();
    if (ioc_type)   params.append("ioc_type", ioc_type);
    if (risk_level) params.append("risk_level", risk_level);
    return download(`/export/csv?${params}`, "export_ti.csv");
  },

  json: ({ ioc_type, risk_level } = {}) => {
    const params = new URLSearchParams();
    if (ioc_type)   params.append("ioc_type", ioc_type);
    if (risk_level) params.append("risk_level", risk_level);
    return download(`/export/json?${params}`, "export_ti.json");
  },

  pdf: ({ ioc_type, risk_level } = {}) => {
    const params = new URLSearchParams();
    if (ioc_type)   params.append("ioc_type", ioc_type);
    if (risk_level) params.append("risk_level", risk_level);
    return download(`/export/pdf?${params}`, "export_ti.pdf");
  },
};