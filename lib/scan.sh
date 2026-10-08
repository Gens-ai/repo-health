# shellcheck shell=bash
# lib/scan.sh — dependency/code scan of one target.
#
# Order: trivy fs -> trivy config (if container files) -> semgrep -> native
# audits (composer / npm / pip-audit). Missing tools are skipped and noted in
# the report, never fatal. Produces $REPORT_DIR/<name>-<ts>.md and .json.
#
# Exit code contract: rh_scan_target returns 1 if any HIGH or CRITICAL finding
# exists (from trivy's own --exit-code, or any parsed finding at that
# severity), 0 otherwise, 2 if the target could not be scanned at all.

# Shared jq helpers: severity normalisation, ranking, stable finding keys.
_RH_JQ_DEFS='
def sev: (. // "UNKNOWN" | tostring | ascii_upcase) as $s
  | if $s == "CRITICAL" then "CRITICAL"
    elif $s == "HIGH" or $s == "ERROR" then "HIGH"
    elif $s == "MEDIUM" or $s == "MODERATE" or $s == "WARNING" then "MEDIUM"
    elif $s == "LOW" or $s == "INFO" then "LOW"
    else "UNKNOWN" end;
def rank: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}[.] // 4;
def norm($tool): {tool: $tool, type: (.type // "finding"), id: (.id // "unknown" | tostring),
    severity: (.severity | sev), title: (.title // "" | tostring | split("\n")[0] | .[0:200]),
    location: (.location // "" | tostring), pkg: (.pkg // "" | tostring), fixed: (.fixed // "" | tostring)}
  | .key = "\(.tool):\(.id):\(.location):\(.pkg)";
'

_RH_JQ_TRIVY='
.Results[]? | .Target as $t
| ( (.Vulnerabilities // [])[]
    | {type: "vuln", id: .VulnerabilityID, severity: .Severity, pkg: .PkgName,
       title: "\(.PkgName) \(.InstalledVersion): \(.Title // .Description // "")",
       location: $t, fixed: (.FixedVersion // "")} ),
  ( (.Secrets // [])[]
    | {type: "secret", id: .RuleID, severity: .Severity, title: .Title,
       location: "\($t):\(.StartLine // 0)"} ),
  ( (.Misconfigurations // [])[] | select((.Status // "FAIL") == "FAIL")
    | {type: "misconfig", id: (.AVDID // .ID), severity: .Severity, title: .Title,
       location: (if (.CauseMetadata.StartLine // 0) > 0 then "\($t):\(.CauseMetadata.StartLine)" else $t end),
       fixed: (.Resolution // "")} )
'

_RH_JQ_SEMGREP='
.results[]?
| {type: "sast", id: .check_id, severity: .extra.severity, title: .extra.message,
   location: "\(.path):\(.start.line)"}
'

_RH_JQ_COMPOSER='
(.advisories // {}) | if type == "object" then to_entries[] else empty end
| .key as $p | .value[]
| {type: "vuln", id: (.cve // .advisoryId), severity: (.severity // "UNKNOWN"), pkg: $p,
   title: "\($p): \(.title)", location: "composer.lock"}
'

_RH_JQ_NPM='
(.vulnerabilities // {}) | to_entries[] | .value as $v
| ($v.via[]? | objects)
| {type: "vuln", pkg: $v.name, severity: .severity, title: "\($v.name): \(.title)",
   id: (((.url // "") | split("/") | last) as $u | if ($u // "") == "" then "npm-\(.source)" else $u end),
   location: "package-lock.json",
   fixed: (if ($v.fixAvailable | type) == "object" then "\($v.fixAvailable.name)@\($v.fixAvailable.version)"
           elif $v.fixAvailable == true then "npm audit fix" else "" end)}
'

_RH_JQ_PIPAUDIT='
(if type == "array" then . else (.dependencies // []) end) | .[]
| .name as $p | .version as $ver | (.vulns // [])[]
| {type: "vuln", id: .id, severity: "UNKNOWN", pkg: $p,
   title: "\($p) \($ver): \(.description // "")", location: "requirements.txt",
   fixed: ((.fix_versions // []) | join(", "))}
'

# _rh_tool <name> <status> <findings> <note> — record one tool's outcome.
_rh_tool() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(printf '%s' "$4" | tr '\t\n' '  ')" >> "$RH_WORK/tools.tsv"
}

# _rh_errtail <file> — last meaningful stderr line, for report notes.
_rh_errtail() {
  grep -v '^[[:space:]]*$' "$1" 2>/dev/null | tail -n 1 | cut -c1-200
}

# _rh_parse <tool-label> <json-file> <jq-filter> — append normalised findings;
# prints how many were added. Fails if the file isn't valid JSON.
_rh_parse() {
  local label=$1 file=$2 filter=$3 before after
  [ "$RH_HAVE_JQ" = 1 ] || { echo "?"; return 0; }
  jq -e . "$file" >/dev/null 2>&1 || return 1
  before=$(wc -l < "$RH_WORK/findings.jsonl")
  jq -c --arg tool "$label" "$_RH_JQ_DEFS ($filter) | norm(\$tool)" "$file" >> "$RH_WORK/findings.jsonl" 2>"$RH_WORK/jq.err" || return 1
  after=$(wc -l < "$RH_WORK/findings.jsonl")
  echo $((after - before))
}

# _rh_md_cell <text> — make text safe inside a markdown table cell.
_rh_md_cell() {
  printf '%s' "$1" | tr '\n' ' ' | sed 's/|/\\|/g'
}

# rh_scan_target <name> <path> <report-dir>
# Sets: RH_SCAN_MD RH_SCAN_JSON RH_SCAN_SUMMARY RH_SCAN_NEW_COUNT RH_SCAN_NEW_TEXT
rh_scan_target() {
  local name=$1 path=$2 report_dir=$3
  local ts stacks rc n note trivy_hit=0 prev="" f exit_code=0
  local -a targs skip

  RH_SCAN_MD="" RH_SCAN_JSON="" RH_SCAN_SUMMARY="" RH_SCAN_NEW_COUNT=0 RH_SCAN_NEW_TEXT=""
  if [ ! -d "$path" ]; then
    rh_err "$name: path does not exist: $path"
    return 2
  fi
  RH_HAVE_JQ=0; command -v jq >/dev/null 2>&1 && RH_HAVE_JQ=1

  ( umask 077; mkdir -p "$report_dir" ) || { rh_err "cannot create report dir $report_dir"; return 2; }
  RH_WORK=$(mktemp -d "${TMPDIR:-/tmp}/repo-health.XXXXXX") || return 2
  : > "$RH_WORK/tools.tsv"; : > "$RH_WORK/findings.jsonl"

  ts=$(date -u +%Y%m%dT%H%M%SZ)
  # Previous run for this target (exact timestamp glob so "app" never matches "app-api").
  for f in "$report_dir/$name"-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.json; do
    [ -f "$f" ] && prev=$f
  done
  # Avoid clobbering if two scans land in the same second.
  while [ -e "$report_dir/$name-$ts.json" ]; do sleep 1; ts=$(date -u +%Y%m%dT%H%M%SZ); done

  stacks=$(rh_detect_stack "$path")
  rh_info "scanning $name ($path)${stacks:+ — stack: $stacks}"

  # When scanning a tree that contains this tool's own home, don't descend
  # into cloned targets or runtime config.
  skip=()
  case "$RH_HOME/" in
    "$path"/*) skip=(--skip-dirs "$RH_CACHE" --skip-dirs "$RH_TARGETS") ;;
  esac

  # 1. trivy fs: dependency CVEs, secrets, misconfig.
  if command -v trivy >/dev/null 2>&1; then
    targs=(fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --format json
           --output "$RH_WORK/trivy-fs.json" --exit-code 3 --quiet)
    [ -f "$path/.trivyignore" ] && targs+=(--ignorefile "$path/.trivyignore")
    [ "${#skip[@]}" -gt 0 ] && targs+=("${skip[@]}")
    rh_info "  trivy fs…"
    trivy "${targs[@]}" "$path" 2>"$RH_WORK/trivy-fs.err"; rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ]; then
      [ "$rc" -eq 3 ] && trivy_hit=1
      if n=$(_rh_parse trivy "$RH_WORK/trivy-fs.json" "$_RH_JQ_TRIVY"); then
        _rh_tool "trivy fs" ran "$n" "vuln, secret, misconfig (HIGH/CRITICAL)"
      else
        _rh_tool "trivy fs" error "?" "could not parse trivy JSON output"
      fi
    else
      _rh_tool "trivy fs" error 0 "exit $rc: $(_rh_errtail "$RH_WORK/trivy-fs.err")"
    fi
  else
    _rh_tool "trivy fs" skipped 0 "trivy not installed — run ./install.sh or see: repo-health doctor"
  fi

  # 2. trivy config: only when container files exist.
  if rh_has_container_files "$path"; then
    if command -v trivy >/dev/null 2>&1; then
      targs=(config --severity HIGH,CRITICAL --format json --output "$RH_WORK/trivy-config.json"
             --exit-code 3 --quiet)
      [ -f "$path/.trivyignore" ] && targs+=(--ignorefile "$path/.trivyignore")
      [ "${#skip[@]}" -gt 0 ] && targs+=("${skip[@]}")
      rh_info "  trivy config…"
      trivy "${targs[@]}" "$path" 2>"$RH_WORK/trivy-config.err"; rc=$?
      if [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ]; then
        [ "$rc" -eq 3 ] && trivy_hit=1
        if n=$(_rh_parse trivy "$RH_WORK/trivy-config.json" "$_RH_JQ_TRIVY"); then
          _rh_tool "trivy config" ran "$n" "Dockerfile / compose (duplicates of trivy fs are merged)"
        else
          _rh_tool "trivy config" error "?" "could not parse trivy JSON output"
        fi
      else
        _rh_tool "trivy config" error 0 "exit $rc: $(_rh_errtail "$RH_WORK/trivy-config.err")"
      fi
    else
      _rh_tool "trivy config" skipped 0 "trivy not installed"
    fi
  else
    _rh_tool "trivy config" n/a 0 "no Dockerfile or docker-compose*.y*ml found"
  fi

  # 3. semgrep SAST.
  if command -v semgrep >/dev/null 2>&1; then
    local -a sargs
    sargs=(scan --config "${SEMGREP_CONFIG:-auto}" --severity ERROR --severity WARNING
           --json --output "$RH_WORK/semgrep.json" --quiet)
    # --config auto requires semgrep's metrics; any other ruleset runs with metrics off.
    [ "${SEMGREP_CONFIG:-auto}" = auto ] || sargs+=(--metrics off)
    rh_info "  semgrep…"
    ( cd "$path" && semgrep "${sargs[@]}" . ) >/dev/null 2>"$RH_WORK/semgrep.err"; rc=$?
    if [ "$rc" -le 1 ] && n=$(_rh_parse semgrep "$RH_WORK/semgrep.json" "$_RH_JQ_SEMGREP"); then
      _rh_tool semgrep ran "$n" "config: ${SEMGREP_CONFIG:-auto}; ERROR→HIGH, WARNING→MEDIUM"
    else
      _rh_tool semgrep error 0 "exit $rc: $(_rh_errtail "$RH_WORK/semgrep.err")"
    fi
  else
    _rh_tool semgrep skipped 0 "not installed, run: sudo apt-get install -y pipx && pipx ensurepath && pipx install semgrep"
  fi

  # 4. Native package-manager audits (supplementary).
  if [ -f "$path/composer.json" ]; then
    if command -v composer >/dev/null 2>&1; then
      rh_info "  composer audit…"
      # Audit the lockfile when there is one; otherwise composer audits vendor/.
      local -a cargs
      cargs=(audit --format=json --no-interaction --working-dir="$path")
      [ -f "$path/composer.lock" ] && cargs+=(--locked)
      composer "${cargs[@]}" >"$RH_WORK/composer.json" 2>"$RH_WORK/composer.err"
      if n=$(_rh_parse composer "$RH_WORK/composer.json" "$_RH_JQ_COMPOSER"); then
        _rh_tool "composer audit" ran "$n" ""
      else
        _rh_tool "composer audit" error 0 "$(_rh_errtail "$RH_WORK/composer.err")"
      fi
    else
      _rh_tool "composer audit" skipped 0 "composer.json present but composer not installed"
    fi
  else
    _rh_tool "composer audit" n/a 0 "no composer.json"
  fi

  if [ -f "$path/package.json" ]; then
    if command -v npm >/dev/null 2>&1; then
      rh_info "  npm audit…"
      ( cd "$path" && npm audit --omit=dev --json ) >"$RH_WORK/npm.json" 2>"$RH_WORK/npm.err"
      if [ "$RH_HAVE_JQ" = 1 ] && note=$(jq -er '.error | select(. != null) | (.summary // .code // "npm audit error")' "$RH_WORK/npm.json" 2>/dev/null); then
        _rh_tool "npm audit" error 0 "$(printf '%s' "$note" | head -n 1)"
      elif n=$(_rh_parse npm "$RH_WORK/npm.json" "$_RH_JQ_NPM"); then
        _rh_tool "npm audit" ran "$n" "--omit=dev"
      else
        _rh_tool "npm audit" error 0 "$(_rh_errtail "$RH_WORK/npm.err")"
      fi
    else
      _rh_tool "npm audit" skipped 0 "package.json present but npm not installed"
    fi
  else
    _rh_tool "npm audit" n/a 0 "no package.json"
  fi

  if [ -f "$path/requirements.txt" ]; then
    if command -v pip-audit >/dev/null 2>&1; then
      rh_info "  pip-audit…"
      ( cd "$path" && pip-audit -r requirements.txt -f json ) >"$RH_WORK/pip.json" 2>"$RH_WORK/pip.err"
      if n=$(_rh_parse pip-audit "$RH_WORK/pip.json" "$_RH_JQ_PIPAUDIT"); then
        _rh_tool "pip-audit" ran "$n" "no severity data from PyPI advisories (reported as UNKNOWN)"
      else
        _rh_tool "pip-audit" error 0 "$(_rh_errtail "$RH_WORK/pip.err")"
      fi
    else
      _rh_tool "pip-audit" skipped 0 "requirements.txt present but pip-audit not installed (pipx install pip-audit)"
    fi
  else
    _rh_tool "pip-audit" n/a 0 "no requirements.txt"
  fi

  _rh_write_reports "$name" "$path" "$report_dir" "$ts" "$stacks" "$prev" "$trivy_hit"
  exit_code=$?
  rm -rf "$RH_WORK"
  return "$exit_code"
}

# _rh_write_reports — merge findings, diff against the previous run, write
# markdown + JSON. Returns the scan exit code.
_rh_write_reports() {
  local name=$1 path=$2 report_dir=$3 ts=$4 stacks=$5 prev=$6 trivy_hit=$7
  local md="$report_dir/$name-$ts.md" json="$report_dir/$name-$ts.json"
  local iso crit=0 high=0 med=0 low=0 unk=0 total=0 new=0 result exit_code=0
  local tools_json="" tool st cnt note sep="" stack_json="" s

  iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  if [ "$RH_HAVE_JQ" = 1 ]; then
    jq -s "$_RH_JQ_DEFS"' unique_by(.key) | sort_by((.severity | rank), .tool, .id)' \
      "$RH_WORK/findings.jsonl" > "$RH_WORK/all.json"
    if [ -n "$prev" ] && jq -e '.findings' "$prev" >/dev/null 2>&1; then
      jq '[.findings[].key]' "$prev" > "$RH_WORK/prev-keys.json"
    else
      echo '[]' > "$RH_WORK/prev-keys.json"
    fi
    jq --slurpfile pk "$RH_WORK/prev-keys.json" 'map(. + {new: (.key as $k | ($pk[0] | index($k)) == null)})' \
      "$RH_WORK/all.json" > "$RH_WORK/all2.json"
    read -r crit high med low unk total new < <(jq -r '
      [ (map(select(.severity=="CRITICAL"))|length), (map(select(.severity=="HIGH"))|length),
        (map(select(.severity=="MEDIUM"))|length), (map(select(.severity=="LOW"))|length),
        (map(select(.severity=="UNKNOWN"))|length), length, (map(select(.new))|length) ] | @tsv' "$RH_WORK/all2.json")
  else
    echo '[]' > "$RH_WORK/all2.json"
  fi

  if [ "$trivy_hit" = 1 ] || [ $((crit + high)) -gt 0 ]; then
    exit_code=1; result=FAIL
  else
    result=PASS
  fi

  # tools -> JSON (built in bash so it works without jq too)
  while IFS=$'\t' read -r tool st cnt note; do
    case "$cnt" in ''|*[!0-9]*) cnt=null ;; esac
    tools_json="$tools_json$sep{\"tool\":\"$(rh_json_escape "$tool")\",\"status\":\"$st\",\"findings\":$cnt,\"note\":\"$(rh_json_escape "$note")\"}"
    sep=","
  done < "$RH_WORK/tools.tsv"
  sep=""
  for s in $stacks; do stack_json="$stack_json$sep\"$s\""; sep=","; done

  {
    printf '{\n  "tool": "repo-health",\n  "version": "%s",\n' "$RH_VERSION"
    printf '  "target": "%s",\n  "path": "%s",\n' "$(rh_json_escape "$name")" "$(rh_json_escape "$path")"
    printf '  "timestamp": "%s",\n  "result": "%s",\n  "exit_code": %d,\n' "$iso" "$result" "$exit_code"
    printf '  "trivy_reported_high_or_critical": %s,\n' "$([ "$trivy_hit" = 1 ] && echo true || echo false)"
    printf '  "findings_parsed": %s,\n' "$([ "$RH_HAVE_JQ" = 1 ] && echo true || echo false)"
    printf '  "previous_report": %s,\n' "$([ -n "$prev" ] && printf '"%s"' "$(rh_json_escape "$prev")" || echo null)"
    printf '  "stacks": [%s],\n' "$stack_json"
    printf '  "counts": {"CRITICAL": %d, "HIGH": %d, "MEDIUM": %d, "LOW": %d, "UNKNOWN": %d, "total": %d, "new": %d},\n' \
      "$crit" "$high" "$med" "$low" "$unk" "$total" "$new"
    printf '  "tools": [%s],\n' "$tools_json"
    printf '  "findings": '
    cat "$RH_WORK/all2.json"
    printf '}\n'
  } > "$json"
  # Pretty-print when possible.
  if [ "$RH_HAVE_JQ" = 1 ] && jq . "$json" > "$RH_WORK/pretty.json" 2>/dev/null; then
    cat "$RH_WORK/pretty.json" > "$json"
  fi
  chmod 600 "$json"

  {
    printf '# repo-health scan: %s\n\n' "$name"
    printf -- '- **Result:** %s (exit %d)\n' "$result" "$exit_code"
    printf -- '- **Path:** `%s`\n' "$path"
    printf -- '- **Date:** %s\n' "$iso"
    printf -- '- **Detected stack:** %s\n' "${stacks:-none detected}"
    if [ -n "$prev" ]; then
      printf -- '- **Compared with:** `%s` (%d new finding(s))\n' "$(basename "$prev")" "$new"
    else
      printf -- '- **Compared with:** no previous run (all findings are new)\n'
    fi
    printf '\n## Summary\n\n| CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Total |\n|---|---|---|---|---|---|\n'
    printf '| %d | %d | %d | %d | %d | %d |\n' "$crit" "$high" "$med" "$low" "$unk" "$total"
    if [ "$trivy_hit" = 1 ] && [ $((crit + high)) -eq 0 ]; then
      printf '\n> trivy exited with its HIGH/CRITICAL exit code but findings could not be parsed (is jq installed?). See the trivy output by re-running `trivy fs %s`.\n' "$path"
    fi
    printf '\n## Tools\n\n| Tool | Status | Findings | Note |\n|---|---|---|---|\n'
    while IFS=$'\t' read -r tool st cnt note; do
      printf '| %s | %s | %s | %s |\n' "$tool" "$st" "$cnt" "$(_rh_md_cell "$note")"
    done < "$RH_WORK/tools.tsv"
    printf '\n## Findings\n\n'
    if [ "$RH_HAVE_JQ" != 1 ]; then
      printf '_jq is not installed, so individual findings were not parsed. Install jq for full reports._\n'
    elif [ "$total" -eq 0 ]; then
      printf 'No findings. 🎉\n'
    else
      printf '| Severity | ID | Title | Location | Fixed in / fix | Tool | New |\n|---|---|---|---|---|---|---|\n'
      jq -r '.[] | [.severity, .id, .title, .location, .fixed, .tool, (if .new then "NEW" else "" end)]
             | map(tostring | gsub("\n"; " ") | gsub("\\|"; "\\|")) | "| " + join(" | ") + " |"' "$RH_WORK/all2.json"
    fi
    printf '\n---\nGenerated by repo-health %s. Machine-readable summary: `%s`\n' "$RH_VERSION" "$(basename "$json")"
  } > "$md"
  chmod 600 "$md"

  RH_SCAN_MD=$md
  RH_SCAN_JSON=$json
  RH_SCAN_NEW_COUNT=$new
  if [ "$RH_HAVE_JQ" = 1 ]; then
    RH_SCAN_SUMMARY="$result: $crit critical, $high high, $med medium, $low low, $unk unknown ($new new)"
  else
    RH_SCAN_SUMMARY="$result: $([ "$trivy_hit" = 1 ] && echo "trivy reported HIGH/CRITICAL findings" || echo "no HIGH/CRITICAL from trivy") (install jq for per-finding counts)"
  fi
  if [ "$new" -gt 0 ]; then
    RH_SCAN_NEW_TEXT=$(jq -r 'map(select(.new)) | .[0:15][] | "\(.severity) \(.id) — \(.title) (\(.location))"' "$RH_WORK/all2.json")
    [ "$new" -gt 15 ] && RH_SCAN_NEW_TEXT="$RH_SCAN_NEW_TEXT"$'\n'"… and $((new - 15)) more"
  fi
  return "$exit_code"
}
