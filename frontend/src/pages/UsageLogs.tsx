import { useEffect, useState } from "react";
import { api, UsageLog } from "../api";

export default function UsageLogs() {
  const [logs, setLogs] = useState<UsageLog[]>([]);

  useEffect(() => {
    api.usageLogs(200).then((r) => setLogs(r.logs)).catch(() => {});
  }, []);

  return (
    <>
      <h1>Usage Logs</h1>
      <p className="subtitle">AI request history — provider, model, latency, and token usage.</p>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Provider</th>
              <th>Model</th>
              <th>Task</th>
              <th>Response (ms)</th>
              <th>Tokens</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{new Date(l.created_at).toLocaleString()}</td>
                <td>{l.provider_name}</td>
                <td>{l.model_name}</td>
                <td>{l.task_type}</td>
                <td>{l.response_time}</td>
                <td>{l.token_usage?.total_tokens ?? "—"}</td>
                <td style={{ color: l.request_status === "success" ? "var(--accent)" : "var(--danger)" }}>{l.request_status}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr><td colSpan={7} className="status-text">No usage yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
