import { useEffect, useState } from "react";
import { api, Provider, AiModel } from "../api";

export interface ModelSelection {
  provider_id: string;
  model: string;
}

export default function AiModelSelector({
  value,
  onChange,
  allowAuto = false,
}: {
  value: ModelSelection;
  onChange: (v: ModelSelection) => void;
  allowAuto?: boolean;
}) {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [models, setModels] = useState<AiModel[]>([]);

  useEffect(() => {
    Promise.all([api.providers(), api.models()]).then(([p, m]) => {
      setProviders(p.providers.filter((x) => x.enabled));
      setModels(m.models);
    }).catch(() => {});
  }, []);

  const provider = providers.find((p) => p.id === value.provider_id);
  const providerModels = models.filter((m) => m.provider_id === value.provider_id && m.is_available);

  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
      <div className="field" style={{ flex: 1, minWidth: 180 }}>
        <label>AI Provider</label>
        <select
          value={value.provider_id}
          onChange={(e) => onChange({ provider_id: e.target.value, model: "" })}
        >
          <option value="">{allowAuto ? "Automatic (first enabled)" : "Select provider…"}</option>
          {providers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.status})
            </option>
          ))}
        </select>
      </div>
      <div className="field" style={{ flex: 1, minWidth: 180 }}>
        <label>AI Model</label>
        <select
          value={value.model}
          onChange={(e) => onChange({ ...value, model: e.target.value })}
          disabled={!value.provider_id}
        >
          <option value="">{provider?.default_model ? `Default: ${provider.default_model}` : "Provider default"}</option>
          {providerModels.map((m) => (
            <option key={m.id} value={m.model_name}>{m.model_display_name}</option>
          ))}
          {provider && !providerModels.length && (
            <option value="__manual">Enter model manually…</option>
          )}
        </select>
        {value.model === "__manual" && (
          <input
            placeholder="model name"
            onChange={(e) => onChange({ ...value, model: e.target.value })}
            style={{ marginTop: 6 }}
          />
        )}
      </div>
    </div>
  );
}
