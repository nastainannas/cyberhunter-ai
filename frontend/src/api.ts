export interface ProviderType {
  key: string;
  name: string;
  type: "local" | "cloud";
  defaultBaseUrl: string;
  apiKeyRequired: boolean;
}

export interface Provider {
  id: string;
  provider_key: string;
  name: string;
  base_url: string;
  type: "local" | "cloud";
  has_api_key: boolean;
  enabled: boolean;
  status: "connected" | "disconnected" | "connecting" | "error" | "not_configured";
  status_message: string | null;
  options: Record<string, any>;
  default_model: string | null;
}

export interface AiModel {
  id: string;
  provider_id: string;
  model_name: string;
  model_display_name: string;
  is_available: boolean;
}

export interface UsageLog {
  id: string;
  provider_name: string;
  model_name: string;
  task_type: string;
  response_time: number;
  token_usage: any;
  request_status: string;
  created_at: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  const data = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }));
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data as T;
}

export const api = {
  providerTypes: () => req<{ providers: ProviderType[] }>("/api/provider-types"),
  providers: () => req<{ providers: Provider[] }>("/api/providers"),
  saveProvider: (body: any) =>
    req<{ provider: Provider }>("/api/providers", { method: "POST", body: JSON.stringify(body) }),
  deleteProvider: (id: string) => req("/api/providers/" + id, { method: "DELETE" }),
  testProvider: (id: string) =>
    req<{ message: string; models: string[] }>(`/api/providers/${id}/test`, { method: "POST" }),
  refreshModels: (id: string) => req<{ models: AiModel[] }>(`/api/providers/${id}/models`, { method: "POST" }),
  models: (providerId?: string) =>
    req<{ models: AiModel[] }>("/api/models" + (providerId ? `?provider_id=${providerId}` : "")),
  usageLogs: (limit = 100) => req<{ logs: UsageLog[] }>(`/api/usage-logs?limit=${limit}`),
  chat: (body: any) => req<any>("/api/chat", { method: "POST", body: JSON.stringify(body) }),
  dnsLookup: (host: string) => req<any>(`/api/tools/dns?host=${encodeURIComponent(host)}`),
  robots: (url: string) => req<any>("/api/tools/robots", { method: "POST", body: JSON.stringify({ url }) }),
  httpMethods: (url: string) => req<any>("/api/tools/httpmethods", { method: "POST", body: JSON.stringify({ url }) }),
  findings: () => req<{ findings: any[] }>("/api/findings"),
  saveFinding: (scan: any) => req("/api/findings", { method: "POST", body: JSON.stringify({ scan }) }),
  deleteFinding: (id: string) => req(`/api/findings/${id}`, { method: "DELETE" }),
  clearFindings: () => req("/api/findings", { method: "DELETE" }),
};

export const PROVIDER_ICONS: Record<string, string> = {
  ollama: "🦙",
  lmstudio: "🖥️",
  gemini: "✨",
  openai: "🟢",
  anthropic: "🅰️",
  deepseek: "🐋",
};
