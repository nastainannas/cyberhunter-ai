import { BaseAdapter, fetchWithTimeout, mapHttpError, ProviderError } from "./base.js";

// Anthropic Messages API: https://api.anthropic.com/v1/messages
export class AnthropicAdapter extends BaseAdapter {
  constructor() {
    super({ key: "anthropic", name: "Anthropic Claude", type: "cloud", defaultBaseUrl: "https://api.anthropic.com", apiKeyRequired: true });
  }

  headers(config) {
    return {
      "Content-Type": "application/json",
      "x-api-key": config.apiKey,
      "anthropic-version": "2023-06-01",
      "anthropic-dangerous-direct-browser-access": "false",
    };
  }

  async testConnection(config) {
    if (!config.apiKey) throw new ProviderError("Anthropic requires an API key.", "AUTH_ERROR", 401);
    // Anthropic has no public "list models" endpoint that is guaranteed; use a minimal message call instead.
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/v1/messages`,
      {
        method: "POST",
        headers: this.headers(config),
        body: JSON.stringify({
          model: config.defaultModel || "claude-haiku-4-5-20251001",
          max_tokens: 1,
          messages: [{ role: "user", content: "ping" }],
        }),
      },
      config.options?.timeoutMs ?? 20000
    );
    if (res.status === 401 || res.status === 403) throw mapHttpError(res, "Anthropic");
    if (!res.ok) throw mapHttpError(res, "Anthropic");
    const data = await res.json();
    return { ok: true, message: "Anthropic connected.", models: config.knownModels ?? [] };
  }

  // Anthropic does not expose a models list endpoint; return curated known models.
  async listModels(config) {
    if (!config.apiKey) throw new ProviderError("Anthropic requires an API key.", "AUTH_ERROR", 401);
    const known = [
      "claude-opus-4-1-20250805",
      "claude-sonnet-4-5-20250929",
      "claude-haiku-4-5-20251001",
    ];
    return known.map((m) => ({ model_name: m, model_display_name: m, capabilities: { note: "Model list curated — verify availability for your account." } }));
  }

  splitMessages(messages) {
    let system;
    const msgs = [];
    for (const m of messages) {
      if (m.role === "system") {
        system = system ? `${system}\n\n${m.content}` : m.content;
        continue;
      }
      msgs.push({ role: m.role === "assistant" ? "assistant" : "user", content: m.content });
    }
    // Anthropic requires alternating roles and first message = user
    const cleaned = [];
    for (const m of msgs) {
      const last = cleaned[cleaned.length - 1];
      if (last && last.role === m.role) last.content += `\n\n${m.content}`;
      else cleaned.push({ ...m });
    }
    while (cleaned.length && cleaned[0].role !== "user") cleaned.shift();
    return { system, messages: cleaned.length ? cleaned : [{ role: "user", content: "ping" }] };
  }

  buildBody(request, config) {
    const { system, messages } = this.splitMessages(request.messages);
    const body = {
      model: request.model || config.defaultModel,
      max_tokens: request.maxTokens ?? config.options?.maxTokens ?? 1024,
      messages,
      stream: !!request.stream,
    };
    if (system) body.system = system;
    const temperature = request.temperature ?? config.options?.temperature;
    if (temperature !== undefined) body.temperature = temperature;
    return body;
  }

  async chat(config, request) {
    if (!config.apiKey) throw new ProviderError("Anthropic requires an API key.", "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/v1/messages`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(this.buildBody({ ...request, stream: false }, config)) },
      config.options?.timeoutMs ?? 120000
    );
    if (!res.ok) throw mapHttpError(res, "Anthropic");
    const raw = await res.json();
    const content = (raw.content ?? []).filter((b) => b.type === "text").map((b) => b.text).join("");
    return {
      content,
      model: raw.model,
      usage: raw.usage ? { prompt_tokens: raw.usage.input_tokens, completion_tokens: raw.usage.output_tokens, total_tokens: (raw.usage.input_tokens ?? 0) + (raw.usage.output_tokens ?? 0) } : null,
      finishReason: raw.stop_reason ?? null,
    };
  }

  async *chatStream(config, request) {
    if (!config.apiKey) throw new ProviderError("Anthropic requires an API key.", "AUTH_ERROR", 401);
    const body = this.buildBody({ ...request, stream: true }, config);
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/v1/messages`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(body) },
      config.options?.timeoutMs ?? 300000
    );
    if (!res.ok) throw mapHttpError(res, "Anthropic");
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
        if (!trimmed.startsWith("data:")) continue;
        try {
          const ev = JSON.parse(trimmed.slice(5));
          if (ev.type === "content_block_delta" && ev.delta?.type === "text_delta") {
            full += ev.delta.text;
            yield { type: "delta", content: ev.delta.text };
          }
          if (ev.type === "message_stop") yield { type: "done", content: full };
        } catch { /* ignore */ }
      }
    }
    yield { type: "done", content: full };
  }
}
