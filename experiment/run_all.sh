#!/usr/bin/env bash
# run_all.sh — Reframed hardening experiment (bidirectional). Each run = one separate
# `docker run` of the tool image's factsheet CLI. Baseline B0 = loosely-configured
# running-example container, no assumptions (matches Hybrid Cloud). Deltas are
# single-variable changes vs B0, moving risk DOWN (hardening) or UP (degradation).
set -u
export MSYS_NO_PATHCONV=1
# Run from the repository root. EXP is the absolute path to experiment/ in a form
# Docker accepts as a bind-mount source (Windows path under Git Bash via `pwd -W`).
REPO="$(pwd -W 2>/dev/null || pwd)"; EXP="$REPO/experiment"
IMG="container-risk-factsheet-api:latest"
COMMIT="$(git rev-parse --short HEAD)"
DIGEST="$(docker image inspect "$IMG" --format '{{.Id}}')"
echo "commit=$COMMIT  image=$DIGEST"

# run <id> <overrides? yes|-> <kb_data_dir|->
run() {
  local id="$1" ov="$2" kb="$3"
  local out="experiment/runs/$id"; mkdir -p "$out/inputs"
  local args=(python -m factsheet.cli generate-factsheet "/work/inputs/$id/docker-compose.yml" \
              --dockerfile "/work/inputs/$id/analyzer.dockerfile" --no-pretty -o "/work/runs/$id/factsheet.json")
  [ "$ov" = "yes" ] && args+=(--overrides "/work/inputs/$id/assumptions.conf")
  local kbnote="baked in image (unedited KB)"
  [ "$kb" != "-" ] && { args+=(--data-dir "/work/$kb"); kbnote="$kb (mounted copy, edited)"; }
  local t0 t1 dt
  t0=$(date +%s.%N)
  docker run --rm -v "$EXP:/work" "$IMG" "${args[@]}" >/dev/null 2>"$out/stderr.log"
  local rc=$?; t1=$(date +%s.%N); dt=$(awk "BEGIN{printf \"%.3f\", $t1-$t0}")
  cp experiment/inputs/$id/* "$out/inputs/" 2>/dev/null
  cat > "$out/meta.json" <<EOF
{"delta_id":"$id","tool_commit":"$COMMIT","image_digest":"$DIGEST","wall_clock_seconds":$dt,
 "exit_code":$rc,"overrides":"$([ "$ov" = yes ] && echo assumptions.conf || echo none)","kb_file":"$kbnote"}
EOF
  printf "%-16s rc=%s  %ss\n" "$id" "$rc" "$dt"
}

echo "===== Baseline ====="
run B0              -    -
echo "===== Hardening: risk DOWN ====="
run HARDEN_ARTEFACT -    -      # bundled artefact hardening: non-root + cap_drop ALL
run HARDEN_TECH     yes  -      # technical assumptions verified Satisfied -> Balanced
run HARDEN_FULL     yes  -      # all families Satisfied -> Production
echo "===== Degradation: risk UP ====="
run DEGRADE_TECH    yes  -      # technical controls verified ABSENT -> Rapid Prototype
run DEGRADE_BREACH  yes  -      # assume-breach (all Dissatisfied) -> High Risk
echo "===== Structural / knowledge ====="
run REMOVE_VOLUME   -    -            # remove host volume -> selective risk removal
run KB_IMPACT       -    kb/d6_data   # raise host-files-exposed impact (HybridCloud node)
echo "DONE."
