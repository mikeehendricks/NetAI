#!/usr/bin/env bash
# NetAI local-AI setup — installs/repairs Ollama, provisions models that the
# installed engine ACTUALLY accepts (verified with live test calls), and wires
# the working model names into /opt/netai/.env. Idempotent: safe to re-run.
#
#   sudo bash /opt/netai/scripts/setup-local-ai.sh
#
# Handles: stale /usr/local installs, the new .tar.zst release format,
# filtered networks (GitHub download; model pulls via the local service API),
# and engines that reject certain architectures (e.g. 'mllama' from
# llama3.2-vision on some builds) by testing fallback models and picking the
# first one that truly loads.
set -uo pipefail

APP_DIR="${NETAI_DIR:-/opt/netai}"
ENV_FILE="$APP_DIR/.env"
OLLAMA_VER="${OLLAMA_VER:-0.34.3}"
BASE_URL="http://127.0.0.1:11434"
SRV="${TMPDIR:-/var/tmp}/netai-ollama-setup"
RAM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
RAM_GB=$(( RAM_KB / 1024 / 1024 ))
say() { echo -e "[local-ai] $*"; }
fail() { echo -e "[local-ai] ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root: sudo bash $0"

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

pull() { # pull <model> — via the service API so files land in the SERVICE's storage
  say "pulling $model..."
  api 3600 /api/pull "{\"name\":\"$1\",\"stream\":false}" >/dev/null 2>&1 \
    || api 3600 /api/pull "{\"model\":\"$1\",\"stream\":false}" >/dev/null 2>&1 \
    || return 1
  return 0
}

have() { api 8 /api/tags | python3 -c "import json,sys;print(any(m['name'].split(':')[0]=='$1'.split(':')[0] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null; }

test_model() { # test_model <name> <label> — a real load+generate round-trip
  local out
  out=$(api 300 /api/chat "{\"model\":\"$1\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly: OK\"}],\"stream\":false}" 2>/dev/null) || return 1
  echo "$out" | grep -q '"message"' || { say "  $1 failed to load: $(echo "$out" | head -c 160)"; return 1; }
  return 0
}

pick_model() { # pick_model <label> <candidates...>  -> echoes working tag
  local label="$1"; shift
  for m in "$@"; do
    # RAM guard: rough (model GB ~= tag number or known); warn only
    if have "$m"; then
      say "$label: $m already present - testing..."
    else
      say "$label: $m not present - pulling (this can take a while)..."
      pull "$m" || { say "  pull of $m failed (network?) - trying next candidate"; continue; }
    fi
    if test_model "$m" "$label"; then
      say "$label: $m WORKS on this engine"
      echo "$m"
      return 0
    fi
  done
  return 1
}

# Candidate lists, ordered by support likelihood + size. llama3.2-vision is
# deliberately LAST: several Ollama builds reject its 'mllama' architecture.
# Override via env, e.g.: LOCALAI_VISION_MODELS="qwen2.5vl:7b" bash setup-local-ai.sh
VISION_CANDIDATES=(${LOCALAI_VISION_MODELS:-qwen2.5vl:7b gemma3:12b minicpm-v moondream llama3.2-vision})
TEXT_CANDIDATES=(${LOCALAI_TEXT_MODELS:-llama3.2:3b qwen2.5:3b qwen2.5:0.5b})

say "server RAM: ${RAM_GB} GB (vision models want 8+ GB, text 3b wants ~4 GB)"

VISION_MODEL=$(pick_model "vision" "${VISION_CANDIDATES[@]}") || VISION_MODEL=""
TEXT_MODEL=$(pick_model "text" "${TEXT_CANDIDATES[@]}") || TEXT_MODEL=""

[ -n "$TEXT_MODEL" ] || [ -n "$VISION_MODEL" ] || fail "no model could be loaded on this engine - see the per-model errors above."

# ---------------------------------------------------------------- 3. wire into NetAI
say "writing AI settings into $ENV_FILE ..."
touch "$ENV_FILE"
python3 - "$ENV_FILE" "$VISION_MODEL" "$TEXT_MODEL" <<'PY'
import sys
path, vision, text = sys.argv[1], sys.argv[2], sys.argv[3]
keys = {"AI_PROVIDER", "OPENAI_BASE_URL", "OPENAI_API_KEY", "OPENAI_VISION_MODEL", "OPENAI_MODEL"}
lines = [l for l in open(path, encoding="utf-8").read().splitlines()
         if l.strip() and l.split("=", 1)[0].strip() not in keys]
lines += ["", "# --- local AI (Ollama) — managed by scripts/setup-local-ai.sh ---",
          "AI_PROVIDER=custom",
          "OPENAI_BASE_URL=http://127.0.0.1:11434/v1",
          "OPENAI_API_KEY=ollama"]
if vision:
    lines.append(f"OPENAI_VISION_MODEL={vision}")
if text:
    lines.append(f"OPENAI_MODEL={text}")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("env updated")
PY

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
exit 0
