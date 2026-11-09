import { useRef, useState } from "react";
import { api } from "../api";
import AiModelSelector, { ModelSelection } from "../components/AiModelSelector";

interface Msg { role: "user" | "assistant" | "system"; content: string }

export default function AiPlayground() {
  const [sel, setSel] = useState<ModelSelection>({ provider_id: "", model: "" });
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<Msg[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [meta, setMeta] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  async function send() {
    const text = input.trim();
    if (!text || streaming) return;
    setError(null);
    setMeta(null);
    const next: Msg[] = [...messages, { role: "user", content: text }];
    setMessages(next);
    setInput("");
    setStreaming(true);

    const assistantIdx = next.length;
    setMessages([...next, { role: "assistant", content: "" }]);

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider_id: sel.provider_id || undefined,
          model: sel.model || undefined,
          messages: next.map((m) => ({ role: m.role, content: m.content })),
          stream: true,
          task_type: "playground",
        }),
      });
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let acc = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          const t = line.trim();
          if (!t.startsWith("data:")) continue;
          try {
            const chunk = JSON.parse(t.slice(5));
            if (chunk.type === "delta") {
              acc += chunk.content;
              setMessages((prev) => {
                const copy = [...prev];
                copy[assistantIdx] = { role: "assistant", content: acc };
                return copy;
              });
            } else if (chunk.type === "meta") {
              setMeta(`${chunk.provider} / ${chunk.model} — ${chunk.elapsed_ms}ms`);
            } else if (chunk.type === "error") {
              setError(chunk.error);
            }
          } catch { /* ignore */ }
        }
      }
      boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
    } catch (e: any) {
      setError(e.message);
      setMessages((prev) => prev.slice(0, -1));
    } finally {
      setStreaming(false);
    }
  }

  return (
    <>
      <h1>AI Playground</h1>
      <p className="subtitle">Test provider connections and model behavior. Playground chats are not used for security scanning.</p>

      <div className="card" style={{ marginBottom: 16 }}>
        <AiModelSelector value={sel} onChange={setSel} allowAuto />
        <div className="btn-row">
          <button className="btn" onClick={() => { setMessages([]); setMeta(null); setError(null); }}>Clear Conversation</button>
          {meta && <span className="status-text">{meta}</span>}
        </div>
      </div>

      {error && <div className="alert">{error}</div>}

      <div className="chat-box" ref={boxRef}>
        {messages.length === 0 && <p className="status-text">No messages yet. Pick a provider and send a prompt.</p>}
        {messages.map((m, i) => (
          <div key={i} className={`msg ${m.role}`}>
            <div className="who">{m.role === "user" ? "You" : "Assistant"}</div>
            <div className="bubble">
              {m.content || (streaming && i === messages.length - 1 ? "…" : "")}
              {m.role === "assistant" && m.content && (
                <button
                  className="btn"
                  style={{ marginTop: 8, fontSize: 11, padding: "3px 8px" }}
                  onClick={() => navigator.clipboard.writeText(m.content)}
                >
                  Copy
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: 10 }}>
        <textarea
          style={{ flex: 1, minHeight: 60, background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--text)", padding: 10 }}
          placeholder="Ask the model anything…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
        />
        <button className="btn primary" onClick={send} disabled={streaming || !input.trim()}>
          {streaming ? "…" : "Send"}
        </button>
      </div>
    </>
  );
}
