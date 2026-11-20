# Sentinel — AI Guardrail & Real-Time Content Arbitration

A small FastAPI application that screens prompts, generates a draft, reviews it in a second pass, and only releases an approved answer. The default local profile uses one compact model sequentially for both passes to keep memory use low. It includes sign-up/sign-in, private document upload/download, profile pictures, and interactive API docs at `/docs`.

## Run locally

Requires Python 3.13 and [Ollama for Windows](https://ollama.com/download/windows). Ollama's current documentation lists the RTX 2060 as supported; use a current NVIDIA driver. See the [Ollama Windows notes](https://github.com/ollama/ollama/blob/main/docs/windows.mdx) and [GPU support list](https://github.com/ollama/ollama/blob/main/docs/gpu.mdx).

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
ollama pull qwen2.5:3b-instruct-q4_K_M
ollama create sentinel-local -f Modelfile
uvicorn app.main:app --reload --env-file .env
```

The selected Qwen2.5 3B Q4_K_M model download is about 1.9 GB. The included `Modelfile` caps context at 4,096 tokens and output at 768 tokens. The model is used for generation and then review in sequence, and the app serializes local arbitration, so Ollama can reuse one loaded copy without concurrent requests multiplying VRAM use. This keeps the model/runtime footprint suitable for a 6 GB GPU more comfortably than loading two models. Actual speed and GPU offload depend on available VRAM, drivers, and other programs using the GPU. Prompts are limited to 6,000 characters to keep the review pass inside the local context budget. The model listing notes that its 3B weights use the Qwen Research License; review the model terms for your intended use.

The exact quantized tag and its size are listed in the [official Ollama model library](https://ollama.com/library/qwen2.5/tags). Ollama's [OpenAI-compatible API](https://github.com/ollama/ollama/blob/main/docs/api/openai-compatibility.mdx) is used locally at `http://127.0.0.1:11434/v1`.

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and create an account. Interactive API docs are at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). In development, data is created in `./data`. To use HTTPS locally or in production, set `COOKIE_SECURE=true`.

The blank example `APP_SECRET` makes the app generate a temporary development secret at startup. Set a persistent random value there if you want the hashed rate-limit buckets to remain stable across restarts.

## Configure the two model calls

The local Ollama profile above is the default. To use the more capable hosted Gemini option, set these values in `.env` for local runs or in Render's environment settings for a deployed app:

```text
LLM_PROVIDER=gemini
GEMINI_API_KEY=your-server-side-key
GEMINI_MODEL=gemini-3.8-flash
GEMINI_REVIEW_MODEL=gemini-3.8-flash
```

The app uses Google's OpenAI-compatible Gemini endpoint, so no extra Python package is needed. Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/api-keys). The key stays on the server: do not put it in browser code or commit it to GitHub. `gemini-3.8-flash` is the default because it is a much larger, more capable model than the local 3B model and is currently listed with free-tier input/output access, subject to account/model availability and quotas. Its free-tier prompts and responses may be used to improve Google's products, so do not send confidential or sensitive information on that tier. Review the current [Gemini model list](https://ai.google.dev/gemini-api/docs/models) and [pricing/data terms](https://ai.google.dev/gemini-api/docs/pricing) before use.

The same Gemini model is used for generation and review by default to avoid requiring two API models; this second pass is a useful check, but it is not an independent model and cannot guarantee truth. For a separately configured reviewer, set `GEMINI_REVIEW_MODEL` to another model available to your key. The model has no web search or document retrieval in this app, so it may still be wrong about facts that need current sources. Uploaded documents are stored as files and are not parsed or sent to the model. If the provider is unavailable or settings are incomplete, the app fails closed with `I dont know` and the cold-start disclaimer. Local HTTP is allowed only for loopback hosts; remote model endpoints must use HTTPS.

To keep using Ollama locally, leave `LLM_PROVIDER=ollama` and the local settings in `.env.example`. The Render blueprint defaults to Gemini; add `GEMINI_API_KEY` as a secret in the Render dashboard after deployment.

Optional brand blocking is configured on the server, as a comma-separated list:

```text
BLOCKED_BRANDS=Example Rival,Another Product
```

The built-in structural checks catch common prompt override and hidden-instruction requests. Tune `app/guardrails.py` and `BLOCKED_BRANDS` for the intended brand and policy; the defaults intentionally do not assume which company owns the deployment.

## Run and deploy

The included `render.yaml` describes a Python 3.13 web service with a free plan. This app intentionally uses SQLite; it does not require Supabase settings. Set `APP_ALLOWED_HOSTS` to the deployment hostname if the host does not provide `RENDER_EXTERNAL_HOSTNAME` automatically. Add `GEMINI_API_KEY` as a secret in the Render dashboard if you use Gemini. The app creates its SQLite database and upload directory under `DATA_DIR` (default `./data`). Free hosts may restart or replace local storage, so SQLite records and uploaded files may not survive restarts or deploys.

For another ASGI host, run:

```bash
uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
```

Set these production values before exposing the app:

```text
ENVIRONMENT=production
APP_SECRET=<at least 32 random characters>
COOKIE_SECURE=true
APP_ALLOWED_HOSTS=<your exact hostname>
```

Registration is open by default for the demo. Set `ALLOW_REGISTRATION=false` after initial account creation if self-service signup is not wanted.

## How it works

1. `PromptGateMiddleware` inspects `/api/chat` requests before route handling. It blocks common prompt injection patterns and configured brand names. A blocked prompt gets the standard fail-closed answer.
2. `/api/chat` requires an authenticated session and CSRF token, then applies per-account request limits.
3. `app/llm.py` sends a draft request to the generation model and an independent review request to the review model. The reviewer returns a JSON approval verdict; after approval, the app releases the original draft only if its deterministic structural checks pass. This avoids depending on a small reviewer model to rewrite or reproduce the full answer.
4. Missing settings, provider errors, timeouts, malformed review responses, or rejected drafts return `I dont know` with: “This service uses free-tier facilities, so cold starts can take some time.” Local inference gets a longer timeout for cold model loading. No provider error details or prompt text are returned to the browser.
5. `/docs` is FastAPI's interactive OpenAPI page. The app also has a dark, responsive browser interface.

## Security and file behavior

- Passwords use Argon2id; login and registration have persistent rate limits. Sessions use random opaque tokens stored only as SHA-256 hashes, `HttpOnly`, `SameSite=Strict` cookies, 12-hour expiry, and CSRF checks on authenticated writes.
- Host validation, same-origin checks, body-size limits, restrictive response headers, no-store API responses, SQLite parameter binding, and per-user document authorization are enabled.
- Document uploads accept arbitrary file types, are stored under random server-generated names, and download as attachments with `nosniff`. Names are retained only as display/download metadata. Each file is limited to 25 MB and each account to 100 MB. Files are not parsed, previewed, or added to model prompts.
- Profile pictures accept PNG, JPEG, WebP, or GIF up to 2 MB. The first frame is resized and re-encoded as PNG before storage.
- For enterprise use, add malware scanning, durable storage, backups, audit retention, stronger account recovery, and organization-specific policies. This demo does not scan files for malware or verify model claims. Configure your model provider's retention and privacy controls before sending prompts.

## Project map

```text
app/
  config.py       Environment configuration
  database.py     SQLite schema and connection management
  guardrails.py   Prompt and answer structure checks
  llm.py          Dual-model generation and review
  main.py         FastAPI routes, middleware, sessions, and file handling
  static/         Cyberpunk dark-mode web interface
requirements.txt  Python dependencies
Modelfile         Local Q4 quantization profile and context limits
render.yaml       Render deployment blueprint
```

The 3B model has less capability than a large hosted model, and using the same weights for both passes makes the review less independent. The structural prompt checks still run before generation, and output checks still run after review. For a stronger independent review model, use a separate small reviewer only if you have enough memory available.
