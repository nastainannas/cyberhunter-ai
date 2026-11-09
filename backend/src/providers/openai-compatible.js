import { BaseAdapter, fetchWithTimeout, normalizeChatResponse, mapHttpError, ProviderError } from "./base.js";

// Shared adapter for OpenAI-compatible chat completions APIs.
// Used by OpenAI and DeepSeek (DeepSeek is OpenAI-compatible per official docs).
export class OpenAICompatibleAdapter extends BaseAdapter {
  constructor(meta) {
    super(meta);
  }

  headers(config) {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.apiKey}`,
    };
  }

  async testConnection(config) {
    if (!config.apiKey) throw new ProviderError(`${this.meta.name} requires an API key.`, "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/models`,
      { headers: this.headers(config) },
      config.options?.timeoutMs ?? 10000
    );
    if (!res.ok) throw mapHttpError(res, this.meta.name);
    const data = await res.json();
    return { ok: true, message: `${this.meta.name} connected — ${data.data?.length ?? 0} model(s) available.`, models: data.data?.map((m) => m.id) ?? [] };
  }

  async listModels(config) {
    if (!config.apiKey) throw new ProviderError(`${this.meta.name} requires an API key.`, "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/models`,
      { headers: this.headers(config) },
      config.options?.timeoutMs ?? 15000
    );
    if (!res.ok) throw mapHttpError(res, this.meta.name);
    const data = await res.json();
    return (data.data ?? []).map((m) => ({
      model_name: m.id,
      model_display_name: m.id,
      capabilities: m,
    }));
  }

  buildBody(request, config) {
    const body = {
      model: request.model,
      messages: request.messages,
      stream: !!request.stream,
    };
    const temperature = request.temperature ?? config.options?.temperature;
    const maxTokens = request.maxTokens ?? config.options?.maxTokens;
    if (temperature !== undefined) body.temperature = temperature;
    if (maxTokens !== undefined) body.max_tokens = maxTokens;
    return body;
  }

  async chat(config, request) {
    if (!config.apiKey) throw new ProviderError(`${this.meta.name} requires an API key.`, "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/chat/completions`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(this.buildBody({ ...request, stream: false }, config)) },
      config.options?.timeoutMs ?? 120000
    );
    if (!res.ok) throw mapHttpError(res, this.meta.name);
    return normalizeChatResponse(await res.json());
  }

  async *chatStream(config, request) {
    if (!config.apiKey) throw new ProviderError(`${this.meta.name} requires an API key.`, "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/chat/completions`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(this.buildBody({ ...request, stream: true }, config)) },
      config.options?.timeoutMs ?? 300000
    );
    if (!res.ok) throw mapHttpError(res, this.meta.name);
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
