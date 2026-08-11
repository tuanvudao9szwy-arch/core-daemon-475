#!/bin/bash
# setup.sh — install deps + build binary (postCreateCommand step 1)
sudo apt-get update -qq > /dev/null 2>&1 || true
sudo apt-get install -y gcc libssl-dev zlib1g-dev cpulimit > /dev/null 2>&1 || true
make minimal 2>&1 | tail -3
echo "[setup] Build done: $(ls -lh tornado 2>/dev/null | awk '{print $5}')"
