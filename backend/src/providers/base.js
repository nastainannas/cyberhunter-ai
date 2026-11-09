// Provider Adapter base — every provider implements this interface.
// config: { baseUrl, apiKey, options: { temperature, maxTokens, timeoutMs, stream } }

export class ProviderError extends Error {
  constructor(message, code = "PROVIDER_ERROR", status = 502) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class BaseAdapter {
  constructor(meta) {
    this.meta = meta; // { key, name, type: 'local'|'cloud', defaultBaseUrl, apiKeyRequired }
  }

  async testConnection(config) {
    throw new Error("testConnection not implemented");
  }

  async listModels(config) {
    throw new Error("listModels not implemented");
  }

  async chat(config, request) {
    throw new Error("chat not implemented");
  }

  async *chatStream(config, request) {
    const res = await this.chat(config, { ...request, stream: false });
    yield { type: "done", ...res };
  }
}

export async function fetchWithTimeout(url, options = {}, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

export function normalizeChatResponse(raw) {
  return {
    content: raw?.choices?.[0]?.message?.content ?? raw?.candidates?.[0]?.content?.parts?.map((p) => p.text).join("") ?? "",
    model: raw?.model,
    usage: raw?.usage ?? null,
    finishReason: raw?.choices?.[0]?.finish_reason ?? raw?.candidates?.[0]?.finishReason ?? null,
  };
}

export function mapHttpError(res, providerName) {
  const status = res.status;
  if (status === 401 || status === 403) return new ProviderError(`Invalid ${providerName} API key or insufficient permissions.`, "AUTH_ERROR", 401);
  if (status === 404) return new ProviderError(`${providerName} endpoint or model not found.`, "NOT_FOUND", 404);
  if (status === 429) return new ProviderError(`${providerName} rate limit or quota exceeded. Try again later.`, "RATE_LIMIT", 429);
  if (status >= 500) return new ProviderError(`${providerName} server error (${status}).`, "UPSTREAM_ERROR", 502);
  return new ProviderError(`${providerName} request failed (${status}).`, "BAD_REQUEST", status);
}
