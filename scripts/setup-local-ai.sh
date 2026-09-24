#!/usr/bin/env bash
# NetAI local-AI setup — installs/repairs Ollama, provisions models that the
# installed engine ACTUALLY accepts (verified with live test calls) and that
# FIT this server's RAM and disk, then wires the working model names into
# /opt/netai/.env. Idempotent: safe to re-run.
#
#   sudo bash /opt/netai/scripts/setup-local-ai.sh
#
# Handles: stale /usr/local installs, the new .tar.zst release format,
# filtered networks (GitHub download; model pulls via the local service API),
# engines that reject certain architectures (e.g. 'mllama' from
# llama3.2-vision on some builds), and small servers (8 GB RAM / 20 GB disk):
# candidate lists are chosen per detected RAM and oversized models are skipped
# instead of swap-thrashing the box.
set -uo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
ENV_FILE="$APP_DIR/.env"
OLLAMA_VER="${OLLAMA_VER:-0.34.3}"
BASE_URL="http://127.0.0.1:11434"
SRV="${TMPDIR:-/var/tmp}/netai-ollama-setup"
RAM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
RAM_GB=$(( RAM_KB / 1024 / 1024 ))
RAM_MARGIN="${LOCALAI_RAM_MARGIN:-1.5}"   # headroom for OS+engine+NetAI, GB
say() { echo -e "[local-ai] $*"; }
fail() { echo -e "[local-ai] ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root: sudo bash $0"

# ------------------------------------------------------- model size estimates
req_ram() { # approx GB of RAM a model needs to load comfortably
  case "$1" in
    qwen2.5vl:7b)    echo 7.5 ;;
    qwen2.5vl:3b)    echo 4.5 ;;
    gemma3:12b)      echo 11 ;;
    minicpm-v)       echo 6 ;;
    moondream)       echo 2.5 ;;
    llama3.2-vision) echo 9 ;;
    llama3.2:3b)     echo 3.2 ;;
    qwen2.5:3b)      echo 3.2 ;;
    qwen2.5:0.5b)    echo 1 ;;
    *)               echo 6.5 ;;
  esac
}
req_dl() { # approx download size in MB (only needed when the model must be pulled)
  case "$1" in
    qwen2.5vl:7b)    echo 6200 ;;
    qwen2.5vl:3b)    echo 3300 ;;
    gemma3:12b)      echo 8100 ;;
    minicpm-v)       echo 5500 ;;
    moondream)       echo 1750 ;;
    llama3.2-vision) echo 8000 ;;
    llama3.2:3b)     echo 2100 ;;
    qwen2.5:3b)      echo 2400 ;;
    qwen2.5:0.5b)    echo 400 ;;
    *)               echo 5000 ;;
  esac
}
models_dir() { # where the ollama service stores models (for the disk check)
  if [ -d /usr/share/ollama ]; then echo /usr/share/ollama
  elif [ -d /var/lib/ollama ]; then echo /var/lib/ollama
  else echo /usr/share; fi
}
free_mb() { df -k -P "$1" 2>/dev/null | awk 'NR==2{print int($4/1024)}'; }

# ---------------------------------------------------------------- 1. ollama engine
need_engine=1
if [ -x /usr/bin/ollama ] && /usr/bin/ollama --version 2>/dev/null | grep -q "$OLLAMA_VER"; then
  need_engine=0
  say "Ollama $OLLAMA_VER already installed at /usr/bin/ollama"
fi

if [ "$need_engine" -eq 1 ]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required (apt-get install -y curl)"
  command -v zstd >/dev/null 2>&1 || { say "installing zstd..."; apt-get install -y -qq zstd >/dev/null 2>&1 || fail "could not install zstd (apt blocked?) - install it manually and re-run"; }
  say "downloading Ollama $OLLAMA_VER from GitHub releases (the old ollama.com .tgz no longer exists)..."
  mkdir -p "$SRV"
  curl -fL --retry 3 --retry-delay 3 -m 1800 -o "$SRV/ollama.tar.zst" \
    "https://github.com/ollama/ollama/releases/download/v${OLLAMA_VER}/ollama-linux-amd64.tar.zst" \
    || fail "download failed. On a filtered network: download
  https://github.com/ollama/ollama/releases/download/v${OLLAMA_VER}/ollama-linux-amd64.tar.zst
  on another machine, copy it to $SRV/ollama.tar.zst and re-run this script."
  systemctl stop ollama 2>/dev/null || true
  say "removing any stale /usr/local copies (old installs shadow the new engine)..."
  rm -f /usr/local/bin/ollama; rm -rf /usr/local/lib/ollama
  say "extracting to /usr ..."
  tar --zstd -C /usr -xf "$SRV/ollama.tar.zst" || fail "extraction failed (need ~4 GB free on /)"
  rm -rf "$SRV"
  hash -r
  [ -x /usr/bin/ollama ] && [ -f /usr/lib/ollama/llama-server ] || fail "release extraction incomplete - /usr/bin/ollama and /usr/lib/ollama/llama-server must exist"
fi

getent group ollama >/dev/null 2>&1 || groupadd -r ollama
id ollama >/dev/null 2>&1 || useradd -r -g ollama -s /bin/false -m -d /usr/share/ollama ollama

if [ -d /run/systemd/system ]; then
  cat > /etc/systemd/system/ollama.service <<EOF
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="OLLAMA_HOST=127.0.0.1:11434"

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now ollama >/dev/null 2>&1 || true
  systemctl restart ollama
  say "ollama systemd service restarted"
else
  pkill -f '/usr/bin/ollama serve' 2>/dev/null || true
  runuser -u ollama -- sh -c "setsid nohup /usr/bin/ollama serve >/var/log/ollama.log 2>&1 &" 2>/dev/null \
    || (setsid nohup /usr/bin/ollama serve >/var/log/ollama.log 2>&1 &)
  sleep 2
  say "ollama started directly (no systemd here)"
fi

for i in $(seq 1 20); do
  curl -sf -m 3 "$BASE_URL/api/version" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf -m 3 "$BASE_URL/api/version" >/dev/null 2>&1 || fail "ollama service did not come up on $BASE_URL (journalctl -u ollama -n 30)"
say "ollama API is up: $(curl -sf -m 3 "$BASE_URL/api/version")"

# ---------------------------------------------------------------- 2. model helpers
api() { curl -sf -m "$1" "$BASE_URL$2" ${3:+-d "$3"}; }

wait_api() { # wait for the API after restarts / OOM storms (up to 30s)
  local i
  for i in $(seq 1 30); do
    api 2 /api/version >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

pull() { # pull <model> — via the service API so files land in the SERVICE's storage
  wait_api || return 1
  say "pulling $1 (this can take a while)..." >&2
  api 3600 /api/pull "{\"name\":\"$1\",\"stream\":false}" >/dev/null 2>&1 \
    || api 3600 /api/pull "{\"model\":\"$1\",\"stream\":false}" >/dev/null 2>&1 \
    || return 1
  return 0
}

have() { # have <tag> — is this EXACT tag already in the library?
  wait_api || return 1
  [ "$(api 8 /api/tags | python3 -c "import json,sys;print(any(m['name']=='$1' or m['name']=='$1:latest' for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null)" = "True" ]
}

test_model() { # test_model <name> — a real load+generate round-trip
  local out
  wait_api || return 1
  if ! out=$(api 300 /api/chat "{\"model\":\"$1\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly: OK\"}],\"stream\":false}" 2>/dev/null); then
    return 1
  fi
  if echo "$out" | grep -q '"message"'; then
    say "  $1 says: $(echo "$out" | python3 -c "import json,sys;print(json.load(sys.stdin)['message']['content'][:40])" 2>/dev/null)" >&2
    return 0
  fi
  say "  $1 load error: $(echo "$out" | head -c 140)" >&2
  return 1
}

pick_model() { # pick_model <label> <candidates...>  -> echoes working tag (progress to stderr)
  # GUARD (global): 1 = apply RAM/disk guards (auto candidate lists);
  #                 0 = operator override list, honor it unconditionally
  local label="$1"; shift
  local m need have_ram free
  for m in "$@"; do
    # RAM guard: never even try a model that would swap-thrash or OOM this box
    if [ "$GUARD" -eq 1 ] && [ "$RAM_GB" -gt 0 ]; then
      need=$(req_ram "$m")
      if awk "BEGIN{exit !($need + $RAM_MARGIN > $RAM_GB)}"; then
        say "$label: $m needs ~${need} GB RAM - this server has ${RAM_GB} GB, skipping (avoid OOM)" >&2
        continue
      fi
    fi
    if have "$m"; then
      say "$label: $m already present - testing..." >&2
    else
      # disk guard: only relevant when a download is actually needed
      free=$(free_mb "$(models_dir)")
      if [ "$GUARD" -eq 1 ] && [ -n "$free" ] && [ "$free" -gt 0 ] && awk "BEGIN{exit !($(req_dl "$m") * 1.1 > $free)}"; then
        say "$label: $m needs ~$(req_dl "$m") MB but only ${free} MB free in $(models_dir) - skipping (free up disk, e.g. ollama rm <model>)" >&2
        continue
      fi
      say "$label: $m not present - pulling..." >&2
      pull "$m" || { say "  pull of $m failed (network?) - trying next candidate" >&2; continue; }
    fi
    if test_model "$m"; then
      say "$label: $m WORKS on this engine" >&2
      echo "$m"
      return 0
    fi
    say "  $m could not load on this engine - trying next candidate" >&2
  done
  return 1
}

# Candidate lists, sized to this server's RAM. llama3.2-vision is deliberately
# LAST everywhere: several Ollama builds reject its 'mllama' architecture.
# Override via env, e.g.: LOCALAI_VISION_MODELS="moondream" bash setup-local-ai.sh
if [ -n "${LOCALAI_VISION_MODELS:-}" ]; then
  VISION_CANDIDATES=($LOCALAI_VISION_MODELS)
elif [ "$RAM_GB" -ge 12 ]; then
  VISION_CANDIDATES=(qwen2.5vl:7b gemma3:12b minicpm-v qwen2.5vl:3b moondream llama3.2-vision)
elif [ "$RAM_GB" -ge 6 ]; then
  VISION_CANDIDATES=(qwen2.5vl:3b moondream minicpm-v llama3.2-vision)
else
  VISION_CANDIDATES=(moondream qwen2.5vl:3b llama3.2-vision)
fi
if [ -n "${LOCALAI_TEXT_MODELS:-}" ]; then
  TEXT_CANDIDATES=($LOCALAI_TEXT_MODELS)
elif [ "$RAM_GB" -ge 6 ]; then
  TEXT_CANDIDATES=(llama3.2:3b qwen2.5:0.5b)
else
  TEXT_CANDIDATES=(qwen2.5:0.5b llama3.2:3b)
fi

say "server RAM: ${RAM_GB} GB - candidate lists sized for this box (margin ${RAM_MARGIN} GB)"
say "disk free for models: $(free_mb "$(models_dir)" || echo '?') MB in $(models_dir)"

GUARD=1
[ -n "${LOCALAI_VISION_MODELS:-}" ] && GUARD=0
VISION_MODEL=$(pick_model "vision" "${VISION_CANDIDATES[@]}") || VISION_MODEL=""
GUARD=1
[ -n "${LOCALAI_TEXT_MODELS:-}" ] && GUARD=0
TEXT_MODEL=$(pick_model "text" "${TEXT_CANDIDATES[@]}") || TEXT_MODEL=""

[ -n "$TEXT_MODEL" ] || [ -n "$VISION_MODEL" ] || fail "no model could be loaded on this engine - see the per-model errors above."

# ---------------------------------------------------------------- 3. wire into NetAI
# Local CPU inference is much slower than cloud APIs, so raise the app's
# request timeouts (defaults 45s/90s would abort mid-generation).
say "writing AI settings into $ENV_FILE ..."
touch "$ENV_FILE"
python3 - "$ENV_FILE" "$VISION_MODEL" "$TEXT_MODEL" <<'PY'
import sys
path, vision, text = sys.argv[1], sys.argv[2], sys.argv[3]
keys = {"AI_PROVIDER", "OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_VISION_MODEL",
        "OPENAI_MODEL", "AI_TEXT_TIMEOUT", "AI_VISION_TIMEOUT"}
lines = [l for l in open(path, encoding="utf-8").read().splitlines()
         if l.strip() and l.split("=", 1)[0].strip() not in keys]
lines += ["", "# --- local AI (Ollama) — managed by scripts/setup-local-ai.sh ---",
          "AI_PROVIDER=custom",
          "OPENAI_BASE_URL=http://127.0.0.1:11434/v1",
          "OPENAI_API_KEY=ollama",
          "AI_TEXT_TIMEOUT=900",
          "AI_VISION_TIMEOUT=900"]
if vision:
    lines.append(f"OPENAI_VISION_MODEL={vision}")
if text:
    lines.append(f"OPENAI_MODEL={text}")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("env updated")
PY

if [ -d /run/systemd/system ] && [ -f /etc/systemd/system/netai.service ] \
   && grep -qE -- "--timeout [0-9]+" /etc/systemd/system/netai.service; then
  cur=$(grep -oE -- "--timeout [0-9]+" /etc/systemd/system/netai.service | head -1 | awk '{print $2}')
  if [ "${cur:-0}" -lt 600 ]; then
    sed -i -E "s/--timeout [0-9]+/--timeout 600/g" /etc/systemd/system/netai.service
    systemctl daemon-reload
    say "raised gunicorn worker timeout ${cur}s -> 600s (local inference runs long)"
  fi
fi

if [ -d /run/systemd/system ] && systemctl cat netai >/dev/null 2>&1; then
  systemctl restart netai && say "netai restarted with the new AI settings"
else
  say "NOTE: restart the NetAI service manually to apply: sudo systemctl restart netai"
fi

# ---------------------------------------------------------------- 4. summary
echo
say "================ LOCAL AI SETUP COMPLETE ================"
[ -n "$VISION_MODEL" ] && say "  Config generator (topology images): $VISION_MODEL" \
                       || say "  Config generator: NO working vision model found - see errors above (RAM? engine support?)"
[ -n "$TEXT_MODEL" ]    && say "  Summary enhancement:               $TEXT_MODEL" \
                       || say "  Summary enhancement: NO working text model found - see errors above"
say "  Verify in NetAI: Admin -> Settings should show 'configured · custom'."
say "  Re-run this script any time - it is safe and will keep what works."
[ -n "$VISION_MODEL" ] || say "  If RAM is tight, add RAM/GPU and re-run: vision needs ~8-10 GB free."
# Dead-weight hint: llama3.2-vision can never load on engines that reject 'mllama'
if api 8 /api/tags 2>/dev/null | grep -q '"name":"llama3.2-vision' \
   && [ "${VISION_MODEL#llama3.2-vision}" = "$VISION_MODEL" ]; then
  say "  Reclaim ~7.8 GB of disk (that model can never load here): ollama rm llama3.2-vision:latest"
fi
exit 0
