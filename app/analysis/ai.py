"""Optional LLM enhancement layer. Works with OpenAI-compatible APIs and Anthropic.
The engine is fully functional without any AI key (deterministic mode)."""
import json
import logging
import re

import requests

log = logging.getLogger("netai.ai")

SYSTEM_PROMPT = (
    "You are a senior network security architect. You receive findings from a deterministic "
    "network-configuration analysis engine and a draft executive summary. Produce an improved, "
    "board-ready executive summary in GitHub-flavoured Markdown (max ~600 words) that: (1) opens with "
    "a 3-sentence risk narrative for non-technical executives, (2) summarises the top risks with plain-"
    "language business impact, (3) gives a prioritised remediation roadmap, and (4) notes any ADDITIONAL "
    "risk patterns you observe that the rule engine may have missed (mark those clearly as 'AI observation'). "
    "Do not invent findings that contradict the data. "
    "Output plain Markdown only: no HTML tags, no HTML entities, and never wrap the answer in ``` fences."
)


def service_error(cfg) -> str:
    """Human-readable reason when the configured OpenAI-compatible service is
    unreachable, or '' if it answers. Used to give precise background-job errors
    (e.g. Ollama not running) instead of a generic 'model returned nothing'."""
    provider = (cfg.get("AI_PROVIDER") or "").lower()
    if provider not in ("openai", "custom"):
        return ""
    base = (cfg.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    try:
        requests.get(base + "/models", timeout=3,
                     headers={"Authorization": "Bearer " + (cfg.get("OPENAI_API_KEY") or "x")})
        return ""
    except requests.exceptions.ConnectionError:
        return (f"could not reach the AI service at {base} - is it running? "
                "check: sudo systemctl status ollama")
    except Exception:
        return ""


def _strip_fence_wrap(text: str) -> str:
    """Small local models often wrap the whole answer in ```markdown fences (sometimes
    unterminated). Strip the wrapping fence lines so the markdown renders normally."""
    t = (text or "").strip()
    if t.startswith("```") and re.match(r"^```[A-Za-z]*\s*$", t.split("\n", 1)[0]):
        t = t.split("\n", 1)[1] if "\n" in t else ""
    if t.rstrip().endswith("```"):
        t = t.rstrip()[:-3]
    return t.strip()


def ai_available(cfg) -> bool:
    provider = (cfg.get("AI_PROVIDER") or "").lower()
    if provider == "openai":
        return bool(cfg.get("OPENAI_API_KEY"))
    if provider == "anthropic":
        return bool(cfg.get("ANTHROPIC_API_KEY"))
    if provider == "custom":
        return bool(cfg.get("OPENAI_BASE_URL") and cfg.get("OPENAI_API_KEY"))
    return False


def enhance(cfg, findings, draft_markdown, progress=None) -> str:
    """Return AI-polished executive summary markdown, or '' when unavailable/failed.

    progress: optional callback(stage, words) for background-job UIs. With a
    callback on the openai/custom providers the request switches to streaming
    so the UI can report real generation progress (word count). stage is
    'load' until the first token arrives, then 'gen'.
    """
    if not ai_available(cfg):
        return ""
    # keep payload small: top findings only
    compact = [
        {k: f.get(k) for k in ("severity", "title", "device", "recommendation", "rule_id")}
        for f in findings[:40]
    ]
    user = (
        f"FINDINGS (JSON): {json.dumps(compact)}\n\n"
        f"DRAFT SUMMARY:\n{draft_markdown[:6000]}\n\n"
        "Return ONLY the improved executive summary markdown."
    )
    provider = (cfg.get("AI_PROVIDER") or "").lower()
    stream = progress is not None and provider in ("openai", "custom")
    try:
        if provider == "anthropic":
            if progress is not None:
                progress("gen", 0)
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": cfg["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": cfg.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
                      "max_tokens": 2000, "system": SYSTEM_PROMPT,
                      "messages": [{"role": "user", "content": user}]},
                timeout=int(cfg.get("AI_TEXT_TIMEOUT") or 45),
            )
            r.raise_for_status()
            return _strip_fence_wrap(r.json()["content"][0]["text"])
        else:  # openai or custom
            base = (cfg.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
            payload = {"model": cfg.get("OPENAI_MODEL", "gpt-4o-mini"),
                       "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                    {"role": "user", "content": user}],
                       "temperature": 0.3, "max_tokens": 2000}
            if not stream:
                r = requests.post(
                    base + "/chat/completions",
                    headers={"Authorization": "Bearer " + cfg["OPENAI_API_KEY"],
                             "Content-Type": "application/json"},
                    json=payload,
                    timeout=int(cfg.get("AI_TEXT_TIMEOUT") or 45),
                )
                r.raise_for_status()
                return _strip_fence_wrap(r.json()["choices"][0]["message"]["content"])
            # streaming: report real progress while tokens arrive
            payload["stream"] = True
            r = requests.post(
                base + "/chat/completions",
                headers={"Authorization": "Bearer " + cfg["OPENAI_API_KEY"],
                         "Content-Type": "application/json", "Accept": "text/event-stream"},
                json=payload,
                timeout=int(cfg.get("AI_TEXT_TIMEOUT") or 45),
                stream=True,
            )
            r.raise_for_status()
            text, words, last_words = [], 0, -1
            for line in r.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    delta = json.loads(data)["choices"][0]["delta"].get("content") or ""
                except (ValueError, KeyError, IndexError, TypeError):
                    continue
                if delta:
                    if last_words < 0:
                        progress("gen", 0)   # first token: model is loaded and generating
                    text.append(delta)
                    words = sum(len(t.split()) for t in text)
                    if words - last_words >= 15:
                        last_words = words
                        progress("gen", words)
            if text:
                return _strip_fence_wrap("".join(text))
            # server ignored stream:true and sent a normal body (or empty) - fall back
            fallback = {k: v for k, v in payload.items() if k != "stream"}
            r2 = requests.post(
                base + "/chat/completions",
                headers={"Authorization": "Bearer " + cfg["OPENAI_API_KEY"],
                         "Content-Type": "application/json"},
                json=fallback,
                timeout=int(cfg.get("AI_TEXT_TIMEOUT") or 45),
            )
            r2.raise_for_status()
            return _strip_fence_wrap(r2.json()["choices"][0]["message"]["content"])
    except Exception as e:
        log.warning("AI enhancement failed: %s", e)
        return ""
