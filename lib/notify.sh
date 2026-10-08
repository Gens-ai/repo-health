# shellcheck shell=bash
# lib/notify.sh — pluggable notification channels.
#
# Every channel is called the same way:   notify "<subject>" "<body>"
# Dispatch is driven by $NOTIFY_CHANNEL, and each channel reads its single
# config value from $NOTIFY_TARGET. Functions return non-zero on failure and
# print the reason to stderr.

# rh_json_escape <string> — escape a string for embedding in a JSON "..." literal.
rh_json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  # Drop any remaining control characters rather than emit invalid JSON.
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

# _rh_oneline <string> — collapse newlines (header values must be single-line).
_rh_oneline() {
  printf '%s' "$1" | tr '\r\n' '  '
}

# _rh_truncate <string> <max-chars>
_rh_truncate() {
  local s=$1 max=$2
  if [ "${#s}" -gt "$max" ]; then
    printf '%s…' "${s:0:$((max - 1))}"
  else
    printf '%s' "$s"
  fi
}

# _rh_http <curl args...> — run curl, succeed only on a 2xx response, and
# surface the response body on failure (APIs like Telegram explain errors there).
_rh_http() {
  local resp code
  if ! resp=$(curl -sS --max-time 20 -w $'\n%{http_code}' "$@" 2>&1); then
    rh_err "notify ($NOTIFY_CHANNEL): request failed: $(_rh_oneline "$resp")"
    return 1
  fi
  code=${resp##*$'\n'}
  case "$code" in
    2??) return 0 ;;
  esac
  rh_err "notify ($NOTIFY_CHANNEL): HTTP $code: $(_rh_truncate "$(_rh_oneline "${resp%$'\n'*}")" 300)"
  return 1
}

notify_ntfy() {
  local subject=$1 body=$2 url=$NOTIFY_TARGET
  # A bare topic goes to the public ntfy.sh server; a full URL supports self-hosting.
  case "$url" in
    http://*|https://*) ;;
    *) url="https://ntfy.sh/$url" ;;
  esac
  _rh_http -H "Title: $(_rh_oneline "$subject")" \
    ${RH_NOTIFY_PRIORITY:+-H "Priority: $RH_NOTIFY_PRIORITY"} \
    --data-raw "$(_rh_truncate "$body" 3500)" "$url"
}

notify_webhook() {
  local subject=$1 body=$2
  _rh_http -X POST -H 'Content-Type: application/json' \
    --data-raw "{\"subject\":\"$(rh_json_escape "$subject")\",\"body\":\"$(rh_json_escape "$body")\"}" \
    "$NOTIFY_TARGET"
}

notify_slack() {
  local subject=$1 body=$2
  _rh_http -X POST -H 'Content-Type: application/json' \
    --data-raw "{\"text\":\"$(rh_json_escape "*$subject*"$'\n'"$body")\"}" \
    "$NOTIFY_TARGET"
}

notify_discord() {
  local subject=$1 body=$2 text
  text=$(_rh_truncate "**$subject**"$'\n'"$body" 1900)   # Discord caps content at 2000 chars
  _rh_http -X POST -H 'Content-Type: application/json' \
    --data-raw "{\"content\":\"$(rh_json_escape "$text")\"}" \
    "$NOTIFY_TARGET"
}

notify_telegram() {
  local subject=$1 body=$2 token chat
  # NOTIFY_TARGET is <bot_token>:<chat_id>; bot tokens themselves contain a
  # colon, so split on the LAST one.
  case "$NOTIFY_TARGET" in
    *:*:*) ;;
    *) rh_err "notify (telegram): NOTIFY_TARGET must be <bot_token>:<chat_id>"; return 1 ;;
  esac
  token=${NOTIFY_TARGET%:*}
  chat=${NOTIFY_TARGET##*:}
  _rh_http -X POST "https://api.telegram.org/bot${token}/sendMessage" \
    --data-urlencode "chat_id=$chat" \
    --data-urlencode "disable_web_page_preview=true" \
    --data-urlencode "text=$(_rh_truncate "$subject"$'\n\n'"$body" 3800)"
}

notify_pushover() {
  local subject=$1 body=$2 app user
  case "$NOTIFY_TARGET" in
    *:*) ;;
    *) rh_err "notify (pushover): NOTIFY_TARGET must be <app_token>:<user_key>"; return 1 ;;
  esac
  app=${NOTIFY_TARGET%%:*}
  user=${NOTIFY_TARGET#*:}
  # --form-string (not -F) so a body starting with '@' is never read as a file.
  _rh_http https://api.pushover.net/1/messages.json \
    --form-string "token=$app" \
    --form-string "user=$user" \
    --form-string "title=$(_rh_truncate "$(_rh_oneline "$subject")" 250)" \
    --form-string "message=$(_rh_truncate "$body" 1000)" \
    ${RH_NOTIFY_PRIORITY:+--form-string "priority=1"}
}

notify_email() {
  local subject to=$NOTIFY_TARGET body=$2 sm="" c
  subject=$(_rh_oneline "$1")
  case "$to" in
    -*|*[[:space:]]*|*@*@*) rh_err "notify (email): invalid recipient address: $to"; return 1 ;;
    ?*@?*) ;;
    *) rh_err "notify (email): invalid recipient address: $to"; return 1 ;;
  esac
  for c in sendmail /usr/sbin/sendmail /usr/lib/sendmail; do
    if command -v "$c" >/dev/null 2>&1; then sm=$(command -v "$c"); break; fi
  done
  if [ -n "$sm" ]; then
    printf 'To: %s\nSubject: %s\nContent-Type: text/plain; charset=UTF-8\n\n%s\n' \
      "$to" "$subject" "$body" | "$sm" -i "$to"
  elif command -v mail >/dev/null 2>&1; then
    printf '%s\n' "$body" | mail -s "$subject" "$to"
  else
    rh_err "notify (email): neither sendmail nor mail is installed"
    return 1
  fi
}

notify_exec() {
  local subject=$1 body=$2
  if [ ! -x "$NOTIFY_TARGET" ]; then
    rh_err "notify (exec): $NOTIFY_TARGET is not an executable file"
    return 1
  fi
  "$NOTIFY_TARGET" "$subject" "$body"
}

# notify "<subject>" "<body>" — send through the configured channel.
# Returns 0 on success, 1 on delivery failure, 2 on misconfiguration,
# 3 if no channel is configured at all.
notify() {
  local subject=$1 body=${2:-}
  if [ -z "${NOTIFY_CHANNEL:-}" ]; then
    rh_warn "no notification channel configured (run: repo-health init)"
    return 3
  fi
  if [ -z "${NOTIFY_TARGET:-}" ]; then
    rh_err "NOTIFY_TARGET is empty in $RH_CONF"
    return 2
  fi
  case "$NOTIFY_CHANNEL" in
    ntfy|webhook|slack|discord|telegram|pushover|email|exec)
      "notify_$NOTIFY_CHANNEL" "$subject" "$body" ;;
    *)
      rh_err "unknown NOTIFY_CHANNEL '$NOTIFY_CHANNEL' (expected: ntfy webhook slack discord telegram pushover email exec)"
      return 2 ;;
  esac
}
