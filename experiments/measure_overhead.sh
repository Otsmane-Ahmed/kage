#!/usr/bin/env bash
#
# Tracing-overhead benchmark for the paper's "Performance overhead" paragraph.
#
# Measures the wall-clock cost of running the BERT baseline workload UNTRACED
# vs. wrapped in the EXACT strace invocation Kage uses
# (src/runtime_tracer.py: strace -f -e trace=openat,connect). Reports mean and
# sample standard deviation over N repetitions so the paper can cite a figure
# with a confidence interval instead of a single point measurement.
#
# Run from the repo root:  bash experiments/measure_overhead.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/experiments/real_test_model.py"
PY="$REPO/venv/bin/python"
N=10
STRACE_LOG="/tmp/strace_output.log"
STATS_FILE="/tmp/overhead_stats.txt"

[ -x "$PY" ] || PY="$(command -v python3)"

# Start from an empty stats file; each run_series appends its mean to it, so the
# final ratio step can read BOTH the baseline and traced means. (Using '>' inside
# awk would truncate the file on the second call and wipe the baseline mean.)
: > "$STATS_FILE"

echo "python : $PY"
echo "script : $SCRIPT"
echo "reps   : $N"
echo

# Warm-up: make sure BERT weights are cached and the OS page cache is warm, so
# we measure tracing overhead, not a one-time model download.
echo "[warm-up] priming model + file caches ..."
"$PY" "$SCRIPT" >/dev/null 2>&1
"$PY" "$SCRIPT" >/dev/null 2>&1
echo "[warm-up] done"
echo

# time_one <label> <cmd...>  ->  echoes elapsed seconds, one per line
run_series () {
  local label="$1"; shift
  local -a times=()
  for i in $(seq 1 "$N"); do
    local s e d
    s=$(date +%s.%N)
    "$@" >/dev/null 2>&1
    e=$(date +%s.%N)
    d=$(awk "BEGIN{printf \"%.6f\", $e - $s}")
    times+=("$d")
    printf "  %-8s run %2d: %6.3fs\n" "$label" "$i" "$d"
  done
  # mean + sample std via awk
  printf '%s\n' "${times[@]}" | awk -v L="$label" '
    { x[NR]=$1; sum+=$1 }
    END {
      n=NR; mean=sum/n; ss=0;
      for(i=1;i<=n;i++){d=x[i]-mean; ss+=d*d}
      sd=(n>1)?sqrt(ss/(n-1)):0;
      printf "  >> %-8s mean=%.3fs  sd=%.3fs  (n=%d)\n", L, mean, sd, n;
      printf "MEAN_%s %.6f\n", L, mean >> "/tmp/overhead_stats.txt"
    }'
}

echo "=== BASELINE (untraced) ==="
run_series baseline "$PY" "$SCRIPT"
echo
echo "=== TRACED (Kage strace) ==="
run_series traced strace -f -e trace=openat,connect -o "$STRACE_LOG" "$PY" "$SCRIPT"

echo
echo "=== OVERHEAD RATIO ==="
awk '
  /MEAN_baseline/ {b=$2}
  /MEAN_traced/   {t=$2}
  END { if (b>0) printf "  traced / baseline = %.2fx  (baseline %.3fs -> traced %.3fs)\n", t/b, b, t }
' /tmp/overhead_stats.txt
