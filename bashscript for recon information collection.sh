#!/usr/bin/env bash
# merged-recon.sh
# Single-file reconnaissance helper for authorized pentesting/info-gathering.
# Features:
#  - prompts for target
#  - START/END markers per step with elapsed time & rc
#  - writes per-step logs to ./recon_<target>_<timestamp>/
#  - asks for sudo once and keeps it alive for the script duration
#  - dry-run mode: ./merged-recon.sh -n
#
# IMPORTANT: Only run against systems you have explicit permission to test.

set -euo pipefail
IFS=$'\n\t'

# ---------- options ----------
DRYRUN=0
while getopts ":n" opt; do
  case $opt in
    n) DRYRUN=1 ;;
    *) echo "Usage: $0 [-n]"; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# ---------- helpers ----------
log() { printf '%s\n' "$*"; }
now_s() { date +%s; }
fmt_duration() {
  local s=$1
  printf '%02dh:%02dm:%02ds' $((s/3600)) $((s%3600/60)) $((s%60))
}

# run_or_print: label cmd...
# writes combined stdout+stderr to ${OUTDIR}/${label}.log and prints to stdout via tee
run_or_print(){
  local label="$1"; shift
  local cmd="$*"
  local start=$(now_s)
  log "========== START: ${label} =========="
  log "COMMAND: ${cmd}"
  if [[ ${DRYRUN} -eq 1 ]]; then
    log "[DRYRUN] Skipping execution"
    log "========== END: ${label} (skipped) =========="
    return 0
  fi

  local outfile="${OUTDIR}/${label}.log"
  # run command with bash -c so complex strings work; stream to tee and capture rc
  bash -c "${cmd}" > >(tee "${outfile}") 2>&1
  local rc=$?
  local stop=$(now_s)
  local dur=$((stop-start))
  if [[ ${rc} -eq 0 ]]; then
    log "========== END: ${label} (OK) — elapsed: $(fmt_duration ${dur}) =========="
  else
    log "========== END: ${label} (FAILED rc=${rc}) — elapsed: $(fmt_duration ${dur}) =========="
  fi
  return ${rc}
}

# ---------- Sudo keep-alive (ask once) ----------
SUDO_KEEPALIVE_PID=""
if [[ $EUID -ne 0 && ${DRYRUN:-0} -eq 0 ]]; then
  echo "[INFO] Requesting sudo password (cached for the script duration)..."
  if sudo -v; then
    # start keepalive in background
    ( while true; do sleep 60; sudo -n true 2>/dev/null || true; done ) &
    SUDO_KEEPALIVE_PID=$!
    # ensure keepalive stopped on exit
    trap 'if [[ -n "${SUDO_KEEPALIVE_PID}" ]]; then kill "${SUDO_KEEPALIVE_PID}" 2>/dev/null || true; fi' EXIT
  else
    echo "[WARN] sudo -v failed (no sudo or wrong password). Some commands may fail later."
  fi
fi

# ---------- Prompt for target (domain/IP or hosts file) ----------
read -r -p $'\nEnter domain or IP to scan (example.com or 192.0.2.1) or path to hosts file: ' INPUT
if [[ -z "${INPUT// /}" ]]; then
  echo "No input provided. Exiting."
  exit 0
fi

# If input is a file: read targets from it; otherwise single target
TARGETS=()
if [[ -f "${INPUT}" ]]; then
  mapfile -t TARGETS < "${INPUT}"
else
  # normalize: strip scheme and trailing slash
  T="${INPUT#http://}"
  T="${T#https://}"
  T="${T%%/*}"
  TARGETS=( "$T" )
fi

read -r -p "Proceed with ${#TARGETS[@]} target(s): ${TARGETS[*]} ? [y/N] " CONF
CONF=${CONF:-N}
if [[ ! $CONF =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# ---------- Prepare output dir for each run (we'll create per-target)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# iterate targets
for TGT in "${TARGETS[@]}"; do
  # trim whitespace
  TGT="$(echo "$TGT" | tr -d $'\r' | xargs)"
  if [[ -z "$TGT" ]]; then continue; fi

  OUTDIR="./recon_${TGT}_${TIMESTAMP}"
  mkdir -p "$OUTDIR" || { echo "Failed to create $OUTDIR"; exit 1; }
  echo
  log "=== Recon for: ${TGT} ==="
  log "Outputs: ${OUTDIR}"
  log "Dry-run: ${DRYRUN}"
  log ""

  # ---------- Steps ----------

  # 1) Ping
  if command -v ping >/dev/null 2>&1; then
    run_or_print "${TGT}_ping" "ping -c 4 -i 0.4 ${TGT}"
  else
    log "[SKIP] ping not installed"
  fi

  # 2) Whois
  if command -v whois >/dev/null 2>&1; then
    run_or_print "${TGT}_whois" "whois ${TGT}"
  else
    log "[SKIP] whois not installed"
  fi

  # 3) DNS: dig + nslookup
  if command -v dig >/dev/null 2>&1; then
    run_or_print "${TGT}_dig" "dig +noall +answer ${TGT}"
  else
    log "[SKIP] dig not installed"
  fi

  if command -v nslookup >/dev/null 2>&1; then
    run_or_print "${TGT}_nslookup" "nslookup ${TGT}"
  else
    log "[SKIP] nslookup not installed"
  fi

  # 4) Nmap quick
  if command -v nmap >/dev/null 2>&1; then
    run_or_print "${TGT}_nmap_quick" "nmap -sS -sV -T4 --reason -Pn -oA \"${OUTDIR}/${TGT}_nmap_quick\" ${TGT}"
  else
    log "[SKIP] nmap not installed"
  fi

  # 5) optional: nmap full (noisy)
  if command -v nmap >/dev/null 2>&1; then
    read -r -p "Run noisy full nmap (UDP + all ports + vuln scripts) on ${TGT}? [y/N] " NF
    NF=${NF:-N}
    if [[ $NF =~ ^[Yy]$ ]]; then
      run_or_print "${TGT}_nmap_full" "sudo nmap -sS -sU -p- -T4 -A -sV -O --osscan-guess --script 'default,vuln' -Pn --reason -v --min-rate 200 -oA \"${OUTDIR}/${TGT}_nmap_full\" ${TGT}"
    else
      log "[SKIP] full nmap"
    fi
  fi

  # 6) hping3 (requires sudo)
  if command -v hping3 >/dev/null 2>&1; then
    run_or_print "${TGT}_hping3" "sudo hping3 -S -p 80 -c 4 -i u1000 --ttl 64 -d 120 --timestamp ${TGT}"
  else
    log "[SKIP] hping3 not installed"
  fi

  # 7) Nikto (web)
  if command -v nikto >/dev/null 2>&1; then
    run_or_print "${TGT}_nikto_https" "nikto -h https://${TGT} -p 443 -ssl -Tuning 123b -o \"${OUTDIR}/${TGT}_nikto.html\" -Format html || true"
    run_or_print "${TGT}_nikto_txt" "nikto -h https://${TGT} -ssl -o \"${OUTDIR}/${TGT}_nikto.txt\" -Format txt || true"
  else
    log "[SKIP] nikto not installed"
  fi

  # 8) Amass passive + optional active
  if command -v amass >/dev/null 2>&1; then
    run_or_print "${TGT}_amass_passive" "amass enum -d ${TGT} -passive -o \"${OUTDIR}/${TGT}_amass_passive.txt\" || true"
    read -r -p "Run active amass brute (noisy) on ${TGT}? [y/N] " AM
    AM=${AM:-N}
    if [[ $AM =~ ^[Yy]$ ]]; then
      WL="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
      RESOLV="/etc/resolv.conf"
      if [[ -f "${WL}" ]]; then
        run_or_print "${TGT}_amass_active" "amass enum -d ${TGT} -active -brute -w \"${WL}\" -r \"${RESOLV}\" -src -ip -dir \"${OUTDIR}/amass_active_${TGT}\" -o \"${OUTDIR}/${TGT}_amass_active.txt\" || true"
      else
        log "[SKIP] amass wordlist not found (${WL})"
      fi
    fi
  else
    log "[SKIP] amass not installed"
  fi

  # 9) ffuf: subdomain & directories
  if command -v ffuf >/dev/null 2>&1; then
    SUBWL="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
    if [[ -f "${SUBWL}" ]]; then
      run_or_print "${TGT}_ffuf_subs" "ffuf -u https://FUZZ.${TGT}/ -w \"${SUBWL}\" -H \"Host: FUZZ.${TGT}\" -t 50 -mc 200,301,302,403 -fs 0 -o \"${OUTDIR}/${TGT}_ffuf_subs.json\" -of json || true"
    else
      log "[SKIP] ffuf subdomain wordlist not found (${SUBWL})"
    fi

    DIRWL="/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt"
    if [[ -f "${DIRWL}" ]]; then
      run_or_print "${TGT}_ffuf_dirs" "ffuf -u https://${TGT}/FUZZ -w \"${DIRWL}\" -e .php,.html,.txt -t 50 -mc 200,301,302,403 -fs 0 -recursion -recursion-depth 2 -o \"${OUTDIR}/${TGT}_ffuf_dirs.json\" -of json || true"
    else
      log "[SKIP] ffuf directory wordlist not found (${DIRWL})"
    fi
  else
    log "[SKIP] ffuf not installed"
  fi

  log ""
  log "=== ALL TASKS COMPLETE for ${TGT} ==="
  log "Results folder: ${OUTDIR}"
  log ""
done

# cleanup keepalive if still running (trap also handles it)
if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
  kill "${SUDO_KEEPALIVE_PID}" 2>/dev/null || true
fi

exit 0

