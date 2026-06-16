#!/usr/bin/env bash
# determinism.sh — each config across N SEPARATE container invocations,
# alternating PYTHONHASHSEED (0/random); count distinct canonical hashes (target 1).
set -u
export MSYS_NO_PATHCONV=1
# Run from the repository root.
EXP="$(pwd -W 2>/dev/null || pwd)/experiment"
IMG="container-risk-factsheet-api:latest"
PY="$([ -x .venv/Scripts/python.exe ] && echo .venv/Scripts/python.exe || echo python)"
TMP="experiment/runs/_determinism"; mkdir -p "$TMP"
echo "label,N,distinct_canonical_hashes,hash" > "$TMP/determinism_results.csv"
det() {  # det <id> <N> <overrides? yes|-> <kb|->
  local id="$1" N="$2" ov="$3" kb="$4" hashes=()
  for i in $(seq 1 "$N"); do
    local envs=(); [ $((i%2)) -eq 0 ] && envs+=(-e PYTHONHASHSEED=0)
    local args=(python -m factsheet.cli generate-factsheet "/work/inputs/$id/docker-compose.yml" \
                --dockerfile "/work/inputs/$id/analyzer.dockerfile" --no-pretty -o "/work/runs/_determinism/cur.json")
    [ "$ov" = "yes" ] && args+=(--overrides "/work/inputs/$id/assumptions.conf")
    [ "$kb" != "-" ] && args+=(--data-dir "/work/$kb")
    docker run --rm -v "$EXP:/work" "${envs[@]}" "$IMG" "${args[@]}" >/dev/null 2>&1
    hashes+=("$($PY experiment/analyze.py hash "$TMP/cur.json")")
  done
  local d; d=$(printf "%s\n" "${hashes[@]}" | sort -u | wc -l | tr -d ' ')
  printf "%-16s N=%-3s distinct=%s  %s\n" "$id" "$N" "$d" "${hashes[0]:0:16}"
  echo "$id,$N,$d,${hashes[0]}" >> "$TMP/determinism_results.csv"
}
echo "=== determinism check ==="
det B0             20 -   -
det HARDEN_TECH     5 yes -
det HARDEN_FULL     5 yes -
det DEGRADE_TECH    5 yes -
det DEGRADE_BREACH  5 yes -
det KB_IMPACT       5 -   kb/d6_data
rm -f "$TMP/cur.json"; echo "DONE."
