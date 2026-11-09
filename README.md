# CYBERHUNTER AI — Multi-Model Engine

Platform cybersecurity dengan integrasi multi-LLM provider (lokal & cloud).

## Struktur

- `backend/` — Node.js + Express. Menangani semua koneksi provider, enkripsi API key (AES-256-GCM), storage JSON di `backend/data/`, dan logging usage.
- `frontend/` — React + Vite + TypeScript. Dark cybersecurity theme.

## Menjalankan (development)

```bash
cd backend && npm install && npm run dev   # http://localhost:8787
cd frontend && npm install && npm run dev  # http://localhost:5173 (proxy /api -> 8787)
```

## Provider yang didukung

| Provider | Tipe | Default Base URL |
|---|---|---|
| Ollama | Local | http://localhost:11434 |
| LM Studio | Local | http://localhost:1234/v1 |
| OpenAI | Cloud | https://api.openai.com/v1 |
| Google Gemini | Cloud | https://generativelanguage.googleapis.com |
| Anthropic Claude | Cloud | https://api.anthropic.com |
| DeepSeek | Cloud | https://api.deepseek.com/v1 |

## Keamanan

- API key dienkripsi AES-256-GCM dengan master key di `backend/data/master.key` (jangan commit).
- API key tidak pernah dikirim kembali ke browser (hanya flag `has_api_key`).
- Provider cloud hanya mengirim data jika pengguna mengonfigurasi & mengaktifkannya.
- Untuk provider lokal saat app di-hosting cloud: gunakan Local AI Gateway/connector — `localhost` tidak dapat dijangkau dari server cloud.

## Status Tahap

- [x] Tahap 1–3: UI AI Configuration, Provider Adapter architecture, Ollama + LM Studio (+cloud adapters)
- [ ] Tahap 4–9: integrasi scanner, AI Router/fallback, comparison, dst.
