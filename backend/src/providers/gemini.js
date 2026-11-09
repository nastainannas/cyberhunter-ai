import { BaseAdapter, fetchWithTimeout, normalizeChatResponse, mapHttpError, ProviderError } from "./base.js";

// Google Gemini API (generativelanguage.googleapis.com)
// https://ai.google.dev/api/generate-content
export class GeminiAdapter extends BaseAdapter {
  constructor() {
    super({ key: "gemini", name: "Google Gemini", type: "cloud", defaultBaseUrl: "https://generativelanguage.googleapis.com", apiKeyRequired: true });
  }

  headers(config) {
    return { "Content-Type": "application/json", "x-goog-api-key": config.apiKey };
  }

  modelUrl(config, model, extra = "") {
    return `${this.meta.defaultBaseUrl}/v1beta/models/${encodeURIComponent(model)}${extra}?key=${encodeURIComponent(config.apiKey)}`;
  }

  async testConnection(config) {
    if (!config.apiKey) throw new ProviderError("Google Gemini requires an API key.", "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(`${this.meta.defaultBaseUrl}/v1beta/models?key=${encodeURIComponent(config.apiKey)}`, {}, config.options?.timeoutMs ?? 10000);
    if (!res.ok) throw mapHttpError(res, "Gemini");
    const data = await res.json();
    return { ok: true, message: "Gemini connected.", models: data.models?.map((m) => m.name?.replace("models/", "")) ?? [] };
  }

  async listModels(config) {
    if (!config.apiKey) throw new ProviderError("Google Gemini requires an API key.", "AUTH_ERROR", 401);
    const res = await fetchWithTimeout(`${this.meta.defaultBaseUrl}/v1beta/models?key=${encodeURIComponent(config.apiKey)}`, {}, config.options?.timeoutMs ?? 15000);
    if (!res.ok) throw mapHttpError(res, "Gemini");
    const data = await res.json();
    return (data.models ?? [])
      .filter((m) => (m.supportedGenerationMethods ?? []).includes("generateContent"))
      .map((m) => ({
        model_name: m.name?.replace("models/", ""),
        model_display_name: m.displayName ?? m.name,
        capabilities: { inputTokenLimit: m.inputTokenLimit, outputTokenLimit: m.outputTokenLimit },
      }));
  }

  toGeminiContents(messages) {
    const contents = [];
    let systemInstruction;
    for (const msg of messages) {
      if (msg.role === "system") {
        systemInstruction = { parts: [{ text: msg.content }] };
        continue;
      }
      const role = msg.role === "assistant" ? "model" : "user";
      const last = contents[contents.length - 1];
      if (last && last.role === role) {
        last.parts.push({ text: msg.content });
      } else {
        contents.push({ role, parts: [{ text: msg.content }] });
      }
    }
    return { contents, systemInstruction };
  }

  buildBody(request, config) {
    const { contents, systemInstruction } = this.toGeminiContents(request.messages);
    const body = { contents };
    if (systemInstruction) body.systemInstruction = systemInstruction;
    const generationConfig = {};
    const temperature = request.temperature ?? config.options?.temperature;
    const maxTokens = request.maxTokens ?? config.options?.maxTokens;
    if (temperature !== undefined) generationConfig.temperature = temperature;
    if (maxTokens !== undefined) generationConfig.maxOutputTokens = maxTokens;
    if (Object.keys(generationConfig).length) body.generationConfig = generationConfig;
    return body;
  }

  async chat(config, request) {
    if (!config.apiKey) throw new ProviderError("Google Gemini requires an API key.", "AUTH_ERROR", 401);
    const model = request.model || config.defaultModel;
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(this.buildBody(request, config)) },
      config.options?.timeoutMs ?? 120000
    );
    if (!res.ok) throw mapHttpError(res, "Gemini");
    const raw = await res.json();
    const text = raw.candidates?.[0]?.content?.parts?.map((p) => p.text).join("") ?? "";
    const usage = raw.usageMetadata
      ? { prompt_tokens: raw.usageMetadata.promptTokenCount, completion_tokens: raw.usageMetadata.candidatesTokenCount, total_tokens: raw.usageMetadata.totalTokenCount }
      : null;
    return { content: text, model, usage, finishReason: raw.candidates?.[0]?.finishReason ?? null };
  }

  async *chatStream(config, request) {
    if (!config.apiKey) throw new ProviderError("Google Gemini requires an API key.", "AUTH_ERROR", 401);
    const model = request.model || config.defaultModel;
    const body = this.buildBody(request, config);
    body.generationConfig = { ...(body.generationConfig ?? {}), ...{ }, };
    const res = await fetchWithTimeout(
      `${this.meta.defaultBaseUrl}/v1beta/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`,
      { method: "POST", headers: this.headers(config), body: JSON.stringify(body) },
      config.options?.timeoutMs ?? 300000
    );
    if (!res.ok) throw mapHttpError(res, "Gemini");
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
          const chunk = JSON.parse(trimmed.slice(5));
          const token = chunk.candidates?.[0]?.content?.parts?.map((p) => p.text).join("") ?? "";
          full += token;
          yield { type: "delta", content: token };
        } catch { /* ignore */ }
      }
    }
    yield { type: "done", content: full };
  }
}
