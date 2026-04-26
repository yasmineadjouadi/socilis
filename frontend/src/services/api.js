const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "API error");
  }
  return res.json();
}

export const authApi = {
  login:  (credentials) => request("/auth/login",  { method: "POST", body: JSON.stringify(credentials) }),
  logout: ()            => request("/auth/logout", { method: "POST" }),
  me:     ()            => request("/auth/me"),
};

export const iocApi = {
  analyze: (ioc, type) =>
    request("/analyze", { method: "POST", body: JSON.stringify({ ioc, type }) }),
};

export const chatApi = {
  ask: (question, model, history = []) =>
    request("/chat", { method: "POST", body: JSON.stringify({ question, model, history }) }),
};

export const usersApi = {
  list:   ()       => request("/users"),
  create: (data)   => request("/users",         { method: "POST",   body: JSON.stringify(data) }),
  remove: (userId) => request(`/users/${userId}`, { method: "DELETE" }),
};