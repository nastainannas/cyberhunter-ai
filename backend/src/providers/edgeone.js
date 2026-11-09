import { OpenAICompatibleAdapter } from "./openai-compatible.js";
import { ProviderError, mapHttpError } from "./base.js";

// EdgeOne Makers — unified AI gateway (pages.edgeone.ai).
// OpenAI-compatible endpoint: https://ai-gateway.edgeone.link/v1
// Auth: Bearer <Makers Models API Key>. Model IDs look like
// "@makers/deepseek-v4-flash" or "vendor/model" (e.g. "openai/gpt-5.5").
export class EdgeOneAdapter extends OpenAICompatibleAdapter {
  constructor() {
    super({
      key: "edgeone",
      name: "EdgeOne Makers",
      type: "cloud",
      defaultBaseUrl: "https://ai-gateway.edgeone.link/v1",
      apiKeyRequired: true,
    });
  }

  // The gateway does not guarantee a standard /models listing — verify the key
  // with a minimal chat completion instead, and degrade gracefully.
  async testConnection(config) {
    if (!config.apiKey) throw new ProviderError(`${this.meta.name} requires an API Key (Makers Models key).`, "AUTH_ERROR", 401);
    try {
      return await super.testConnection(config);
    } catch (e) {
      // /models may 404 — fall back to a 1-token chat ping to validate the key
      try {
        await this.chat(config, {
          model: config.defaultModel || "@makers/deepseek-v4-flash",
          messages: [{ role: "user", content: "ping" }],
          maxTokens: 1,
        });
        return { ok: true, message: `${this.meta.name} connected — API key valid (chat ping OK).`, models: [] };
      } catch (e2) {
        throw e2 instanceof ProviderError ? e2 : mapHttpError(e2, this.meta.name);
      }
    }
  }

  async listModels(config) {
    try {
      return await super.listModels(config);
    } catch {
      return []; // gateway may not expose /models — user enters model ID manually
    }
  }
}
