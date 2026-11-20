#!/bin/bash
# G3 broken-chain matrix — for each hop N, swap ONLY hop N to its patched
# version, keep all other hops vulnerable, run the chain; it must die at hop N.
# Usage: ./g3_broken_chain.sh   (from g2_fullchain/)
set -u
cd "$(dirname "$0")"

declare -A PATCHED=(
  [1]="HOP1_VERSION=4.18.0"
  [2]="HOP2_VERSION=0.7.0"
  [3]="HOP3_VERSION=1.17.0"
  [4]="HOP4_VERSION=4.48.0"
  [5]="HOP5_VERSION=3.14.0"
)
declare -A VULN=(
  [1]="HOP1_VERSION=4.17.0"
  [2]="HOP2_VERSION=0.5.1"
  [3]="HOP3_VERSION=1.16.0"
  [4]="HOP4_VERSION=4.47.1"
  [5]="HOP5_VERSION=3.13.2"
)

ALL_VULN="${VULN[1]} ${VULN[2]} ${VULN[3]} ${VULN[4]} ${VULN[5]}"
PASS=0; FAIL=0

SVC() { case $1 in 1) echo hop1_panel;; 2) echo hop2_model_a;; 3) echo hop3_agentbox;; 4) echo hop4_convert_c;; 5) echo hop5_keras_c;; esac; }

for N in 1 2 3 4 5; do
  # restore ALL services to vulnerable versions first (previous config may
  # have left a patched image running)
  export $ALL_VULN
  docker compose -p chain-g2 up -d --build "$(SVC 1)" "$(SVC 2)" "$(SVC 3)" "$(SVC 4)" "$(SVC 5)" > /dev/null 2>&1

  # now swap ONLY hop N to its patched version
  ENVVARS=""
  for M in 1 2 3 4 5; do
    if [ "$M" = "$N" ]; then ENVVARS="$ENVVARS ${PATCHED[$M]}"; else ENVVARS="$ENVVARS ${VULN[$M]}"; fi
  done
  echo "=== G3 config N=$N: hop$N patched ($(echo ${PATCHED[$N]#*=})) ==="
  export $ENVVARS
  if ! docker compose -p chain-g2 up -d --build "$(SVC $N)" 2>&1 | tail -2; then
    echo "[G3] hop$N patched build FAILED"; FAIL=$((FAIL+1)); continue
  fi
  # give hop5 (amd64) time to boot if we touched it
  sleep 45
  # run the chain; expect it to die at hop N
  OUT=$(docker exec chain_attacker python /chain/run_chain.py 2>&1)
  RC=$(echo "$OUT" | grep -o "CHAIN BROKE AT HOP [0-9]" | tail -1)
  if echo "$OUT" | grep -q "FULL CHAIN COMPLETE"; then
    echo "[G3] UNEXPECTED: chain COMPLETED with hop$N patched — G3 FAIL"
    FAIL=$((FAIL+1))
  elif echo "$RC" | grep -q "HOP $N$"; then
    echo "[G3] PASS: chain broke at hop$N as expected ($RC)"
    PASS=$((PASS+1))
  else
    echo "[G3] FAIL: chain broke elsewhere than hop$N: $RC"
    FAIL=$((FAIL+1))
  fi
  echo "$OUT" | tail -6
  echo
done
echo "=== G3 result: PASS=$PASS FAIL=$FAIL (expect 5/0) ==="
