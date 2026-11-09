import { BaseAdapter, fetchWithTimeout, normalizeChatResponse, mapHttpError } from "./base.js";

// Ollama native API: http://localhost:11434
export class OllamaAdapter extends BaseAdapter {
  constructor() {
    super({ key: "ollama", name: "Ollama Local", type: "local", defaultBaseUrl: "http://localhost:11434", apiKeyRequired: false });
  }

  base(config) {
    return (config.baseUrl || this.meta.defaultBaseUrl).replace(/\/$/, "");
  }

  async testConnection(config) {
    const res = await fetchWithTimeout(`${this.base(config)}/api/tags`, {}, config.options?.timeoutMs ?? 8000);
    if (!res.ok) throw mapHttpError(res, "Ollama");
    const data = await res.json();
    const count = data.models?.length ?? 0;
    return { ok: true, message: `Ollama connected — ${count} model(s) available.`, models: data.models?.map((m) => m.name) ?? [] };
  }

  async listModels(config) {
    const res = await fetchWithTimeout(`${this.base(config)}/api/tags`, {}, config.options?.timeoutMs ?? 10000);
    if (!res.ok) throw mapHttpError(res, "Ollama");
    const data = await res.json();
    return (data.models ?? []).map((m) => ({
      model_name: m.name,
      model_display_name: m.name,
      capabilities: { size: m.size, family: m.details?.family, parameter_size: m.details?.parameter_size },
    }));
  }

  async chat(config, request) {
    const body = {
      model: request.model,
      messages: request.messages,
      stream: false,
      options: {
        temperature: request.temperature ?? config.options?.temperature,
        num_ctx: request.contextWindow ?? config.options?.contextWindow,
      },
    };
    const res = await fetchWithTimeout(
      `${this.base(config)}/api/chat`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
      config.options?.timeoutMs ?? 120000
    );
    if (!res.ok) throw mapHttpError(res, "Ollama");
    const raw = await res.json();
    return {
      content: raw.message?.content ?? "",
      model: raw.model ?? request.model,
      usage: { prompt_tokens: raw.prompt_eval_count, completion_tokens: raw.eval_count, total_tokens: (raw.prompt_eval_count ?? 0) + (raw.eval_count ?? 0) },
      finishReason: raw.done_reason ?? null,
    };
  }

  async *chatStream(config, request) {
    const body = {
      model: request.model,
      messages: request.messages,
      stream: true,
      options: { temperature: request.temperature ?? config.options?.temperature, num_ctx: request.contextWindow ?? config.options?.contextWindow },
    };
    const res = await fetchWithTimeout(
      `${this.base(config)}/api/chat`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
      config.options?.timeoutMs ?? 300000
    );
    if (!res.ok) throw mapHttpError(res, "Ollama");
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
        if (!line.trim()) continue;
        try {
          const chunk = JSON.parse(line);
          const token = chunk.message?.content ?? "";
          full += token;
          yield { type: "delta", content: token, done: chunk.done };
        } catch { /* ignore partial json */ }
      }
    }
    yield { type: "done", content: full };
  }
}
