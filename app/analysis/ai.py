"""Optional LLM enhancement layer. Works with OpenAI-compatible APIs and Anthropic.
The engine is fully functional without any AI key (deterministic mode)."""
import json
import logging

import requests

log = logging.getLogger("netai.ai")

SYSTEM_PROMPT = (
    "You are a senior network security architect. You receive findings from a deterministic "
    "network-configuration analysis engine and a draft executive summary. Produce an improved, "
    "board-ready executive summary in GitHub-flavoured Markdown (max ~600 words) that: (1) opens with "
    "a 3-sentence risk narrative for non-technical executives, (2) summarises the top risks with plain-"
    "language business impact, (3) gives a prioritised remediation roadmap, and (4) notes any ADDITIONAL "
    "risk patterns you observe that the rule engine may have missed (mark those clearly as 'AI observation'). "
    "Do not invent findings that contradict the data."
)


def ai_available(cfg) -> bool:
    provider = (cfg.get("AI_PROVIDER") or "").lower()
    if provider == "openai":
        return bool(cfg.get("OPENAI_API_KEY"))
    if provider == "anthropic":
        return bool(cfg.get("ANTHROPIC_API_KEY"))
    if provider == "custom":
        return bool(cfg.get("OPENAI_BASE_URL") and cfg.get("OPENAI_API_KEY"))
    return False


def enhance(cfg, findings, draft_markdown) -> str:
    """Return AI-polished executive summary markdown, or '' when unavailable/failed."""
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
    try:
        if provider == "anthropic":
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
            return r.json()["content"][0]["text"]
        else:  # openai or custom
            base = (cfg.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
            r = requests.post(
                base + "/chat/completions",
                headers={"Authorization": "Bearer " + cfg["OPENAI_API_KEY"],
                         "Content-Type": "application/json"},
                json={"model": cfg.get("OPENAI_MODEL", "gpt-4o-mini"),
                      "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                   {"role": "user", "content": user}],
                      "temperature": 0.3, "max_tokens": 2000},
                timeout=int(cfg.get("AI_TEXT_TIMEOUT") or 45),
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        log.warning("AI enhancement failed: %s", e)
        return ""
