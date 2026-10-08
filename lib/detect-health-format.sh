# shellcheck shell=bash
# lib/detect-health-format.sh — classify a health-endpoint response.
#
# Result is one of OK | DEGRADED | DOWN, plus the detected format:
#   jsonpath  HEALTH_STATUS_JSONPATH override (explicit config wins)
#   fleet     {status: ok|degraded|down, timestamp, checks: {name: {status, critical, ...}}}
#   ietf      draft-inadarei-api-health-check: {status: pass|warn|fail, checks: {...}}
#   generic   anything else: 2xx = healthy (liveness-only)
#   http      non-2xx response
# jq is used when available; without it a grep-based fallback handles simple shapes.

# rh_health_match <value> — the matching rule for HEALTH_STATUS_JSONPATH values.
# Case-insensitive, surrounding whitespace/quotes ignored:
#   OK:       ok pass passed passing up healthy true yes on green success good alive ready running 1
#   DEGRADED: warn warning degraded partial yellow
#   DOWN:     everything else (false, null, 0, down, fail, missing field, ...)
rh_health_match() {
  local v
  v=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -e 's/^[[:space:]"]*//' -e 's/[[:space:]"]*$//')
  case "$v" in
    ok|pass|passed|passing|up|healthy|true|yes|on|green|success|good|alive|ready|running|1) echo OK ;;
    warn|warning|degraded|partial|yellow) echo DEGRADED ;;
    *) echo DOWN ;;
  esac
}

# _rh_generic_status <value> — top-level "status" in an otherwise unrecognised
# 2xx body: explicit failure words mean DOWN, warning words DEGRADED, anything
# else (including no status at all) is healthy.
_rh_generic_status() {
  local v
  v=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$v" in
    down|fail|failed|failing|error|unhealthy|critical|red|false) echo DOWN ;;
    warn|warning|degraded|partial|yellow) echo DEGRADED ;;
    *) echo OK ;;
  esac
}

# rh_health_classify <body-file> <content-type> <http-code> [<jsonpath>]
# Prints: STATUS<TAB>FORMAT<TAB>DETAIL
rh_health_classify() {
  if command -v jq >/dev/null 2>&1; then
    _rh_classify_jq "$@"
  else
    _rh_classify_grep "$@"
  fi
}

_rh_classify_jq() {
  local body=$1 ctype=$2 code=$3 jsonpath=${4:-} is_json=0 fmt res val st
  jq -e 'type == "object" or type == "array"' "$body" >/dev/null 2>&1 && is_json=1

  case "$code" in
    2??) ;;
    *)
      st=""
      [ "$is_json" = 1 ] && st=$(jq -r 'if type=="object" and (.status|type)=="string" then " (status: \(.status))" else "" end' "$body" 2>/dev/null)
      printf 'DOWN\thttp\tHTTP %s%s\n' "$code" "$st"
      return ;;
  esac

  # Explicit override from the target config.
  if [ -n "$jsonpath" ]; then
    if [ "$is_json" != 1 ]; then
      printf 'DOWN\tjsonpath\tbody is not JSON, cannot read %s\n' "$jsonpath"
      return
    fi
    if ! val=$(jq -r "($jsonpath) | if . == null then \"null\" elif type == \"string\" then . else tojson end" "$body" 2>/dev/null); then
      printf 'DOWN\tjsonpath\tinvalid HEALTH_STATUS_JSONPATH: %s\n' "$jsonpath"
      return
    fi
    val=$(printf '%s' "$val" | head -n 1)
    printf '%s\tjsonpath\t%s = %s\n' "$(rh_health_match "$val")" "$jsonpath" "$val"
    return
  fi

  if [ "$is_json" != 1 ]; then
    printf 'OK\tgeneric\tHTTP %s (no JSON body)\n' "$code"
    return
  fi

  local health_json=false
  case "$ctype" in *application/health+json*) health_json=true ;; esac

  fmt=$(jq -r --argjson hj "$health_json" '
    if type != "object" then "generic"
    else (.status | if type == "string" then ascii_downcase else "" end) as $s
      | if (["ok","degraded","down"] | index($s)) != null and (.checks | type) == "object" then "fleet"
        elif (["pass","warn","fail"] | index($s)) != null then "ietf"
        elif $hj and $s != "" then "ietf"
        else "generic" end
    end' "$body" 2>/dev/null) || fmt=generic

  case "$fmt" in
    fleet)
      res=$(jq -r '
        def lc: if type=="string" then ascii_downcase else "" end;
        (.checks | to_entries | map(select(.value | type == "object"))) as $c
        | ($c | map(select(.value.critical == true and (.value.status | lc) == "down"))) as $crit
        | (if ($crit | length) > 0 then "DOWN"
           else ({"ok":"OK","degraded":"DEGRADED","down":"DOWN"}[.status | lc]) end) as $st
        | ($c | map(select((.value.status // "ok" | lc) != "ok"))
              | map("\(.key)=\(.value.status)"
                    + (if .value.critical == true then " (critical)" else "" end)
                    + (if (.value.short_summary // .value.message) != null
                       then ": " + ((.value.short_summary // .value.message) | tostring) else "" end))
              | join("; ")) as $d
        | (if ($crit | length) > 0 and (.status | lc) != "down"
           then "critical check down overrides top-level status \"\(.status)\"; " else "" end) as $pre
        | "\($st)\t\($pre)\(if $d == "" then "status=\(.status)" else $d end)"' "$body" 2>/dev/null) \
        || res=$'DOWN\tunparseable fleet response'
      printf '%s\tfleet\t%s\n' "${res%%$'\t'*}" "${res#*$'\t'}" ;;
    ietf)
      res=$(jq -r '
        def lc: if type=="string" then ascii_downcase else "" end;
        ({"pass":"OK","ok":"OK","up":"OK","warn":"DEGRADED","fail":"DOWN","error":"DOWN","down":"DOWN"}[.status | lc] // "DOWN") as $st
        | ((.checks // {}) | if type == "object" then to_entries else [] end
           | map(.key as $k | (.value | if type == "array" then .[] else . end)
                 | select(type == "object")
                 | select((.status // "pass" | lc) as $s | $s != "pass" and $s != "ok" and $s != "up")
                 | "\($k)=\(.status)" + (if .output then ": " + (.output | tostring) else "" end))
           | join("; ")) as $d
        | ([ (if .output then (.output | tostring) else empty end), (if $d != "" then $d else empty end) ] | join("; ")) as $all
        | "\($st)\t\(if $all == "" then "status=\(.status)" else $all end)"' "$body" 2>/dev/null) \
        || res=$'DOWN\tunparseable health+json response'
      printf '%s\tietf\t%s\n' "${res%%$'\t'*}" "${res#*$'\t'}" ;;
    *)
      val=$(jq -r 'if type=="object" and (.status|type)=="string" then .status else "" end' "$body" 2>/dev/null)
      if [ -n "$val" ]; then
        printf '%s\tgeneric\tHTTP %s, status=%s\n' "$(_rh_generic_status "$val")" "$code" "$val"
      else
        printf 'OK\tgeneric\tHTTP %s\n' "$code"
      fi ;;
  esac
}

# Fallback without jq: reads the first "status" string in the body, which is
# the top-level one for virtually every real health endpoint. The fleet
# critical-check override and nested JSONPATHs need jq.
_rh_classify_grep() {
  local body=$1 code=$3 jsonpath=${4:-} st st_lc s key val
  _rh_grep_field() {
    tr -d '\n' < "$body" | grep -Eo "\"$1\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|true|false|null|-?[0-9.]+)" \
      | head -n 1 | sed -E 's/^"[^"]*"[[:space:]]*:[[:space:]]*//; s/^"(.*)"$/\1/'
  }
  st=$(_rh_grep_field status)
  st_lc=$(printf '%s' "$st" | tr '[:upper:]' '[:lower:]')

  case "$code" in
    2??) ;;
    *) printf 'DOWN\thttp\tHTTP %s%s\n' "$code" "${st:+ (status: $st)}"; return ;;
  esac

  if [ -n "$jsonpath" ]; then
    key=${jsonpath##*.}
    key=${key//[\"\[\]]/}
    val=$(_rh_grep_field "$key")
    [ -n "$val" ] || val=null
    printf '%s\tjsonpath\t%s = %s (grep fallback, install jq for exact paths)\n' "$(rh_health_match "$val")" "$jsonpath" "$val"
    return
  fi

  case "$st_lc" in
    ok|degraded|down)
      if grep -q '"checks"' "$body"; then
        case "$st_lc" in ok) s=OK ;; degraded) s=DEGRADED ;; *) s=DOWN ;; esac
        printf '%s\tfleet\tstatus=%s (install jq for per-check detail)\n' "$s" "$st"
        return
      fi ;;
    pass|warn|fail)
      case "$st_lc" in pass) s=OK ;; warn) s=DEGRADED ;; *) s=DOWN ;; esac
      printf '%s\tietf\tstatus=%s\n' "$s" "$st"
      return ;;
  esac
  if [ -n "$st" ]; then
    printf '%s\tgeneric\tHTTP %s, status=%s\n' "$(_rh_generic_status "$st")" "$code" "$st"
  else
    printf 'OK\tgeneric\tHTTP %s\n' "$code"
  fi
}
