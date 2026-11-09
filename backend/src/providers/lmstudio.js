import { BaseAdapter, fetchWithTimeout, normalizeChatResponse, mapHttpError, ProviderError } from "./base.js";

// LM Studio exposes an OpenAI-compatible API at http://localhost:1234/v1
export class LMStudioAdapter extends BaseAdapter {
  constructor() {
    super({ key: "lmstudio", name: "LM Studio", type: "local", defaultBaseUrl: "http://localhost:1234/v1", apiKeyRequired: false });
  }

  base(config) {
    return (config.baseUrl || this.meta.defaultBaseUrl).replace(/\/$/, "");
  }

  headers(config) {
    const h = { "Content-Type": "application/json" };
    if (config.apiKey) h["Authorization"] = `Bearer ${config.apiKey}`;
    return h;
  }

  async testConnection(config) {
    const res = await fetchWithTimeout(`${this.base(config)}/models`, { headers: this.headers(config) }, config.options?.timeoutMs ?? 8000);
    if (res.status === 401) throw new ProviderError("LM Studio requires an API key (set in LM Studio server settings).", "AUTH_ERROR", 401);
    if (!res.ok) throw mapHttpError(res, "LM Studio");
    const data = await res.json();
    const count = data.data?.length ?? 0;
    return { ok: true, message: `LM Studio connected — ${count} model(s) loaded.`, models: data.data?.map((m) => m.id) ?? [] };
  }

  async listModels(config) {
    const res = await fetchWithTimeout(`${this.base(config)}/models`, { headers: this.headers(config) }, config.options?.timeoutMs ?? 10000);
    if (!res.ok) throw mapHttpError(res, "LM Studio");
    const data = await res.json();
    return (data.data ?? []).map((m) => ({ model_name: m.id, model_display_name: m.id, capabilities: m }));
  }

  buildBody(request, config) {
    return {
      model: request.model,
      messages: request.messages,
      temperature: request.temperature ?? config.options?.temperature,
      max_tokens: request.maxTokens ?? config.options?.maxTokens,
      stream: !!request.stream,
    };
  }

  async chat(config, request) {
    const res = await fetchWithTimeout(
      `${this.base(config)}/chat/completions`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(this.buildBody({ ...request, stream: false }, config)) },
      config.options?.timeoutMs ?? 120000
    );
    if (!res.ok) throw mapHttpError(res, "LM Studio");
    return normalizeChatResponse(await res.json());
  }

  async *chatStream(config, request) {
    const res = await fetchWithTimeout(
      `${this.base(config)}/chat/completions`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(this.buildBody({ ...request, stream: true }, config)) },
      config.options?.timeoutMs ?? 300000
    );
    if (!res.ok) throw mapHttpError(res, "LM Studio");
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let full = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed === "data: [DONE]") continue;
        if (!trimmed.startsWith("data:")) continue;
        try {
          const chunk = JSON.parse(trimmed.slice(5));
          const token = chunk.choices?.[0]?.delta?.content ?? "";
          full += token;
          yield { type: "delta", content: token };
        } catch { /* ignore */ }
      }
    }
    yield { type: "done", content: full };
  }
}
