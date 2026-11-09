import { OllamaAdapter } from "./ollama.js";
import { LMStudioAdapter } from "./lmstudio.js";
import { OpenAICompatibleAdapter } from "./openai-compatible.js";
import { GeminiAdapter } from "./gemini.js";
import { AnthropicAdapter } from "./anthropic.js";
import { EdgeOneAdapter } from "./edgeone.js";

// AI Provider Manager — registry of all adapters.
const adapters = new Map();

function register(adapter) {
  adapters.set(adapter.meta.key, adapter);
}

register(new OllamaAdapter());
register(new LMStudioAdapter());
register(
  new OpenAICompatibleAdapter({
    key: "openai",
    name: "OpenAI GPT",
    type: "cloud",
    defaultBaseUrl: "https://api.openai.com/v1",
    apiKeyRequired: true,
  })
);
register(new GeminiAdapter());
register(new AnthropicAdapter());
register(new EdgeOneAdapter());
register(
  new OpenAICompatibleAdapter({
    key: "deepseek",
    name: "DeepSeek",
    type: "cloud",
    defaultBaseUrl: "https://api.deepseek.com/v1",
    apiKeyRequired: true,
  })
);

export function listProviderTypes() {
  return [...adapters.values()].map((a) => ({
    key: a.meta.key,
    name: a.meta.name,
    type: a.meta.type,
    defaultBaseUrl: a.meta.defaultBaseUrl,
    apiKeyRequired: a.meta.apiKeyRequired,
  }));
}

export function getAdapter(key) {
  const adapter = adapters.get(key);
  if (!adapter) throw new Error(`Unknown provider: ${key}`);
  return adapter;
}

export function isKnownProvider(key) {
  return adapters.has(key);
}
