import { useCallback, useEffect, useState } from "react";
import { api, Provider, ProviderType, PROVIDER_ICONS, AiModel } from "../api";

const STATUS_LABEL: Record<string, string> = {
  connected: "Connected",
  disconnected: "Disconnected",
  connecting: "Connecting…",
  error: "Error",
  not_configured: "Not Configured",
};

export default function AiConfiguration() {
  const [types, setTypes] = useState<ProviderType[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [models, setModels] = useState<AiModel[]>([]);
  const [editing, setEditing] = useState<{ type: ProviderType; provider?: Provider } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [t, p, m] = await Promise.all([api.providerTypes(), api.providers(), api.models()]);
    setTypes(t.providers);
    setProviders(p.providers);
    setModels(m.models);
  }, []);

  useEffect(() => { load().catch((e) => setToast(e.message)); }, [load]);

  const providerFor = (key: string) => providers.find((p) => p.provider_key === key);
  const modelsFor = (providerId?: string) => models.filter((m) => m.provider_id === providerId && m.is_available);

  async function testProvider(p: Provider) {
    setBusyId(p.id);
    setToast(null);
    try {
      const r = await api.testProvider(p.id);
      setToast(`${p.name}: ${r.message}`);
      await load();
    } catch (e: any) {
      setToast(`${p.name}: ${e.message}`);
      await load();
    } finally {
      setBusyId(null);
    }
  }

  async function disconnect(p: Provider) {
    setBusyId(p.id);
    try {
      await api.saveProvider({ id: p.id, provider_key: p.provider_key, enabled: false });
      await load();
    } catch (e: any) {
      setToast(e.message);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <h1>AI Configuration</h1>
      <p className="subtitle">Multi-Model Engine — connect local and cloud AI providers.</p>

      {toast && <div className="notice">{toast}</div>}

      <div className="notice" style={{ marginBottom: 20 }}>
        Local providers (Ollama, LM Studio) run on <em>your</em> machine. If CYBERHUNTER is hosted in the cloud,
        localhost URLs are unreachable — use the Local AI Gateway/connector or a reachable LAN address.
        Cloud providers send your prompts to the provider — enable only providers you trust.
      </div>

      <div className="grid">
        {types.map((t) => {
          const p = providerFor(t.key);
          const status = p?.status ?? "not_configured";
          const activeModels = p ? modelsFor(p.id) : [];
          return (
            <div className="card" key={t.key}>
              <div className="card-header">
                <span className="icon">{PROVIDER_ICONS[t.key] ?? "🤖"}</span>
                <div>
                  <div className="title">{t.name}</div>
                  <div className="status-text">
                    <span className={`dot ${status}`} /> {STATUS_LABEL[status]}
                  </div>
                </div>
                <span className="type-badge">{t.type === "local" ? "LOCAL" : "CLOUD"}</span>
              </div>

              <div className="status-text" style={{ marginBottom: 8 }}>
                {p ? (
                  <>
                    <div>Base URL: {p.base_url}</div>
                    <div>
                      Active model: <strong>{p.default_model || "—"}</strong>
                      {activeModels.length > 0 && ` (${activeModels.length} available)`}
                    </div>
                    {p.status_message && <div className={status === "error" ? "status-text error" : ""}>{p.status_message}</div>}
                  </>
                ) : (
                  "Not configured yet."
                )}
              </div>

              <div className="btn-row">
                <button className="btn primary" onClick={() => setEditing({ type: t, provider: p })}>
                  Configure
                </button>
                {p && (
                  <>
                    <button className="btn" disabled={busyId === p.id} onClick={() => testProvider(p)}>
                      Test Connection
                    </button>
                    <button className="btn" onClick={() => disconnect(p)} disabled={busyId === p.id}>
                      Disconnect
                    </button>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {editing && (
        <ProviderConfigModal
          type={editing.type}
          provider={editing.provider}
          existingModels={editing.provider ? modelsFor(editing.provider.id) : []}
          onClose={() => setEditing(null)}
          onSaved={async () => { setEditing(null); await load(); }}
        />
      )}
    </>
  );
}

function ProviderConfigModal({
  type,
  provider,
  existingModels,
  onClose,
  onSaved,
}: {
  type: ProviderType;
  provider?: Provider;
  existingModels: AiModel[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(provider?.name ?? type.name);
  const [baseUrl, setBaseUrl] = useState(provider?.base_url ?? type.defaultBaseUrl);
  const [apiKey, setApiKey] = useState("");
  const [defaultModel, setDefaultModel] = useState(provider?.default_model ?? "");
  const [temperature, setTemperature] = useState(provider?.options?.temperature?.toString() ?? "");
  const [maxTokens, setMaxTokens] = useState(provider?.options?.maxTokens?.toString() ?? "");
  const [timeoutMs, setTimeoutMs] = useState(provider?.options?.timeoutMs?.toString() ?? "");
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setBusy("save");
    setError(null);
    try {
      const options: any = {};
      if (temperature !== "") options.temperature = parseFloat(temperature);
      if (maxTokens !== "") options.maxTokens = parseInt(maxTokens, 10);
      if (timeoutMs !== "") options.timeoutMs = parseInt(timeoutMs, 10);
      await api.saveProvider({
        id: provider?.id,
        provider_key: type.key,
        name,
        base_url: baseUrl,
        api_key: apiKey, // empty string = keep existing; backend never returns keys
        default_model: defaultModel || null,
        enabled,
        options,
      });
      onSaved();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  }

  async function test() {
    if (!provider) {
      setError("Save the configuration first, then test the connection.");
      return;
    }
    setBusy("test");
    setError(null);
    setMessage(null);
    try {
      const r = await api.testProvider(provider.id);
      setMessage(r.message);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  }

  async function refreshModels() {
    if (!provider) {
      setError("Save the configuration first.");
      return;
    }
    setBusy("models");
    setError(null);
    try {
      const r = await api.refreshModels(provider.id);
      setMessage(`Loaded ${r.models.length} model(s).`);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    if (!provider) return;
    if (!confirm(`Delete configuration for ${provider.name}? This removes the stored API key.`)) return;
    setBusy("delete");
    try {
      await api.deleteProvider(provider.id);
      onSaved();
    } catch (e: any) {
      setError(e.message);
      setBusy(null);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Configure {type.name}</h2>

        {type.type === "cloud" && (
          <div className="alert">Cloud provider — prompts and findings sent to this provider leave your machine. Only enable providers you trust.</div>
        )}
        {type.type === "local" && (
          <div className="notice">Local provider — the backend connects to a server on your machine/LAN. If the app is cloud-hosted, configure a reachable address or Local AI Gateway.</div>
        )}

        <div className="field">
          <label>Provider Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label>Base URL</label>
          <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          <div className="hint">Default: {type.defaultBaseUrl}</div>
        </div>
        <div className="field">
          <label>API Key {provider?.has_api_key && <span className="tag">saved — enter new to replace</span>}</label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={provider?.has_api_key ? "•••••••• (stored encrypted)" : type.apiKeyRequired ? "Required" : "Optional"}
            autoComplete="off"
          />
          <div className="hint">Stored encrypted on the backend. Never sent back to the browser.</div>
        </div>
        <div className="field">
          <label>Active Model</label>
          <input value={defaultModel} onChange={(e) => setDefaultModel(e.target.value)} placeholder="e.g. llama3.1, gpt-4o-mini, gemini-2.0-flash" />
          {existingModels.length > 0 && (
            <select value={defaultModel} onChange={(e) => setDefaultModel(e.target.value)} style={{ marginTop: 6 }}>
              <option value="">— pick from discovered models —</option>
              {existingModels.map((m) => (
                <option key={m.id} value={m.model_name}>{m.model_display_name}</option>
              ))}
            </select>
          )}
          <div className="hint">Use Refresh Models after a successful test to discover available models.</div>
        </div>
        <div className="field">
          <label>Temperature (0–2, optional)</label>
          <input value={temperature} onChange={(e) => setTemperature(e.target.value)} placeholder="e.g. 0.2" />
        </div>
        <div className="field">
          <label>Max Output Tokens (optional)</label>
          <input value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)} placeholder="e.g. 2048" />
        </div>
        <div className="field">
          <label>Timeout (ms)</label>
          <input value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)} placeholder="e.g. 120000" />
        </div>
        <div className="field checkbox">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} id="prov-enabled" />
          <label htmlFor="prov-enabled">Enable Provider</label>
        </div>

        {message && <div className="notice">{message}</div>}
        {error && <div className="alert">{error}</div>}

        <div className="btn-row">
          <button className="btn primary" onClick={save} disabled={busy !== null}>Save Configuration</button>
          <button className="btn" onClick={test} disabled={busy !== null}>Test Connection</button>
          <button className="btn" onClick={refreshModels} disabled={busy !== null}>Refresh Models</button>
          {provider && <button className="btn danger" onClick={remove} disabled={busy !== null}>Delete Configuration</button>}
          <button className="btn" onClick={onClose} style={{ marginLeft: "auto" }}>Close</button>
        </div>
      </div>
    </div>
  );
}
