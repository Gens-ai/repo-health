# shellcheck shell=bash
# lib/ping.sh — one health-endpoint check for one target.
#
# Expects the target's T_* variables to be loaded (see rh_load_target).
# Tracks last-known status in targets.d/<name>.state and only notifies on a
# state change: into DOWN, into DEGRADED, or recovery back to OK.

# _rh_state_get <state-file> <KEY>
_rh_state_get() {
  [ -f "$1" ] || return 0
  sed -n "s/^$2=//p" "$1" | head -n 1
}

# rh_ping_target — sets RH_PING_STATUS (OK|DEGRADED|DOWN); returns 1 if DOWN.
rh_ping_target() {
  local name=$T_NAME url=$T_HEALTH_URL work out rc code secs ms ctype
  local result status fmt detail hname envname hval
  local state="$RH_TARGETS/$name.state" prev since now subject body notify_rc=0

  work=$(mktemp -d "${TMPDIR:-/tmp}/repo-health.XXXXXX") || return 2
  local -a args
  args=(-sS -L --max-time "${PING_TIMEOUT:-10}" -o "$work/body" -D "$work/headers"
        -w '%{http_code} %{time_total}' -A "repo-health/$RH_VERSION"
        -H 'Accept: application/health+json, application/json;q=0.9, */*;q=0.5')

  status="" fmt="-" detail=""
  if [ -n "${T_HEALTH_AUTH_HEADER:-}" ]; then
    # Format: "Header-Name: ENV_VAR_NAME" — the value is read from that
    # environment variable at runtime and never stored in the target file.
    hname=${T_HEALTH_AUTH_HEADER%%:*}
    envname=${T_HEALTH_AUTH_HEADER#*:}
    envname=$(printf '%s' "$envname" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^env://' -e 's/^\$//' -e 's/^{\(.*\)}$/\1/')
    case "$envname" in
      ''|[!A-Za-z_]*|*[!A-Za-z0-9_]*)
        status=DOWN detail="HEALTH_AUTH_HEADER must look like 'Header-Name: ENV_VAR_NAME'" ;;
      *)
        hval=${!envname-}
        if [ -z "$hval" ]; then
          status=DOWN detail="auth env var \$$envname is not set (needed for HEALTH_AUTH_HEADER)"
        else
          # Pass the header via a mode-600 file so the secret never shows up in `ps`.
          ( umask 077; printf '%s: %s\n' "$hname" "$hval" > "$work/auth-header" )
          args+=(-H "@$work/auth-header")
        fi ;;
    esac
  fi

  ms="-"
  if [ -z "$status" ]; then
    out=$(curl "${args[@]}" "$url" 2>"$work/err"); rc=$?
    if [ "$rc" -ne 0 ]; then
      status=DOWN
      detail="request failed: $(tr '\n' ' ' < "$work/err" | sed 's/^curl: ([0-9]*) //; s/[[:space:]]*$//')"
    else
      code=${out%% *}
      secs=${out#* }
      ms=$(awk -v s="$secs" 'BEGIN { printf "%d", s * 1000 }')
      ctype=$(grep -i '^content-type:' "$work/headers" | tail -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr '[:upper:]' '[:lower:]')
      result=$(rh_health_classify "$work/body" "$ctype" "$code" "${T_HEALTH_STATUS_JSONPATH:-}")
      status=${result%%$'\t'*}; result=${result#*$'\t'}
      fmt=${result%%$'\t'*};    detail=${result#*$'\t'}
    fi
  fi
  rm -rf "$work"

  RH_PING_STATUS=$status
  printf '%-24s %-9s %-9s %7s  %s\n' "$name" "$status" "$fmt" "${ms}ms" "$detail"

  # --- state tracking + notification on change ---
  prev=$(_rh_state_get "$state" STATUS)
  since=$(_rh_state_get "$state" SINCE)
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  [ "$prev" = "$status" ] && [ -n "$since" ] || since=$now

  subject="" body=""
  if [ "$status" != "$prev" ]; then
    case "$status" in
      DOWN)
        subject="[repo-health] $name is DOWN"; RH_NOTIFY_PRIORITY=high ;;
      DEGRADED)
        subject="[repo-health] $name is DEGRADED" ;;
      OK)
        case "$prev" in DOWN|DEGRADED) subject="[repo-health] $name recovered (OK)" ;; esac ;;
    esac
  fi
  if [ -n "$subject" ]; then
    body="$url"$'\n'"Status: $status (was: ${prev:-unknown})"$'\n'"Format: $fmt"$'\n'"Detail: $detail"$'\n'"Checked: $now from $(hostname 2>/dev/null || echo unknown)"
    notify "$subject" "$body"; notify_rc=$?
    unset RH_NOTIFY_PRIORITY
  fi

  # If delivery failed, keep the previous status so the next ping retries the
  # notification instead of silently swallowing the state change.
  if [ "$notify_rc" -eq 1 ] || [ "$notify_rc" -eq 2 ]; then
    rh_warn "$name: notification failed; will retry on next ping"
    status=${prev:-UNKNOWN}
    since=$(_rh_state_get "$state" SINCE)
  fi
  {
    printf 'STATUS=%s\n' "$status"
    printf 'SINCE=%s\n' "${since:-$now}"
    printf 'LAST_CHECK=%s\n' "$now"
    printf 'LAST_RESULT=%s\n' "$RH_PING_STATUS"
    printf 'DETAIL=%s\n' "$(printf '%s' "$detail" | tr '\n' ' ')"
  } > "$state.tmp.$$" && chmod 600 "$state.tmp.$$" && mv -f "$state.tmp.$$" "$state"

  [ "$RH_PING_STATUS" = DOWN ] && return 1
  return 0
}
