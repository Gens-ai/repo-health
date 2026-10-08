# repo-health — Build Plan

A free, generic, stack-agnostic CLI that combines (1) dependency/code security
scanning and (2) health-endpoint monitoring for any git repo or running
service. Built to replace paid, rate-limited SaaS scanners with free,
locally-run, unlimited scanning — and to be genuinely usable by strangers,
not just the author.

Author: Joe (joe@gens.dev). License: MIT. Target repo: a new standalone
public GitHub repo (NOT inside any existing project) — author will push it
to GitHub under the Gens-ai org after this build.

## Why this exists (context for whoever builds it)

- Paid SaaS scanners typically cap free usage by test count per month.
  Free OSS tools (trivy, semgrep, native package-manager audit commands)
  have NO limits and cover the same ground.
- The author also wants it to check HTTP health-check endpoints
  (liveness/readiness), because that's a separate but related "is this
  service okay" concern many self-hosted projects care about.
- Must NOT assume Telegram, or any specific notification channel — must be
  genuinely generic so anyone on any stack can configure it in minutes.

## Non-negotiable design decisions already made

1. **Name:** `repo-health` (binary name), NOT "repo-scan" (user explicitly
   rejected anything with "scan" in it — felt like it implied
   snooping/stealing secrets rather than a helpful check).
2. **No hardcoded notification channel.** Must support a pluggable notifier
   system, config-driven, so Telegram is just ONE option among several.
3. **Must support adding repos/targets incrementally** without re-running
   a setup wizard and without hand-editing one shared comma-list config.
4. **Must separate two very different cadences**: dependency/code scans
   (infrequent — nightly) vs. health-endpoint pings (frequent — every
   1-5 min). These are different workloads with different costs.
5. **Zero required paid accounts.** Every bundled scanner/notifier must
   have a free tier that requires no credit card. ntfy.sh (no signup at
   all) should be the easy/default notify option.
6. **Bash + POSIX tools only for the core** (no new language runtime
   requirement) — it must run on any Linux/macOS box with bash, curl,
   and whatever scanner binaries it shells out to. Document a Windows
   path (WSL/Git Bash) rather than supporting it natively.

## Repository layout

```
repo-health/
  bin/
    repo-health              # main dispatcher script (entry point)
  lib/
    notify.sh                 # one function per notification channel
    detect-stack.sh           # per-repo stack detection (composer/npm/pip/go/etc.)
    detect-health-format.sh   # health endpoint JSON shape detection
    scan.sh                   # runs trivy/semgrep/native audits for one target
    ping.sh                   # runs one health-endpoint check for one target
  targets.d/                  # created at runtime, NOT committed (gitignored)
    .gitkeep
  repo-health.conf.example    # global config template (notify channel + creds)
  install.sh                  # fetches/checks trivy, offers pipx+semgrep install
  README.md                   # full user-facing docs (see "README requirements" below)
  LICENSE                     # MIT
  .gitignore                  # repo-health.conf, targets.d/*.conf, *.log, security-scans/
```

## CLI surface (subcommands)

```
repo-health init                     # one-time: pick notify channel, enter its config value, writes repo-health.conf
repo-health doctor                   # checks for trivy/semgrep/composer/npm/pip-audit/etc, prints install cmd per missing tool, per-OS
repo-health add <path>               # register a local repo path, auto-detects stack, writes targets.d/<name>.conf
repo-health add --git <url> [--name X]   # shallow-clones url into a local cache dir, then registers it
repo-health add --url <health-url> [--name X]  # health-ping-only target, no repo/scan
repo-health list                     # table of registered targets: name, mode (scan/ping/both), path/url
repo-health remove <name>
repo-health edit <name>              # opens targets.d/<name>.conf in $EDITOR
repo-health scan [<name>|--all]      # run dependency/code scan for one or all scan-mode targets
repo-health ping [<name>|--all]      # run health-endpoint check for one or all ping-mode targets
repo-health notify-test              # sends a test notification through the configured channel, to verify setup
```

Global config (`repo-health.conf`, mode 600, gitignored):
```
NOTIFY_CHANNEL=ntfy          # ntfy | webhook | slack | discord | telegram | pushover | email | exec
NOTIFY_TARGET=<channel-specific value — ntfy topic / webhook URL / bot token+chat id / etc>
REPORT_DIR=~/security-scans  # where markdown + json reports land
```

Per-target config (`targets.d/<name>.conf`, mode 600):
```
NAME=upwork-prospects
MODE=scan            # scan | ping | both
PATH=/var/www/upwork-prospects    # for scan mode
HEALTH_URL=https://example.com/up # for ping mode
HEALTH_STATUS_JSONPATH=           # optional override for custom health JSON shapes, e.g. ".data.ok"
HEALTH_AUTH_HEADER=                # optional, e.g. "X-Health-Token: <value-from-env-var-name>"
```

## Scanning behavior (the "scan" subcommand)

For each scan-mode target, in this order, skipping any tool that's not
installed (and noting that in the report rather than failing):

1. **Trivy filesystem scan** (`trivy fs --scanners vuln,secret,misconfig
   --severity HIGH,CRITICAL <path>`) — covers dependency CVEs across
   npm/yarn/pnpm, composer, pip/poetry/pipenv, go.mod, cargo, Maven/Gradle,
   NuGet lockfiles natively, PLUS secrets detection and IaC/misconfig.
2. **Trivy config scan** if a Dockerfile or docker-compose*.y*ml is present.
3. **Semgrep** (`semgrep scan --config auto --severity ERROR --severity
   WARNING <path>`) if installed — SAST, multi-language via its auto
   ruleset. Note "not installed, run: sudo apt-get install -y pipx &&
   pipx ensurepath && pipx install semgrep" if missing, don't fail.
4. **Native package-manager audits** as a supplementary pass, run only if
   the matching lockfile/manifest exists:
   - `composer audit` if composer.json present
   - `npm audit --omit=dev` if package.json present
   - `pip-audit -r requirements.txt` if requirements.txt present

Output: a markdown report at `$REPORT_DIR/<name>-<timestamp>.md`, AND a
machine-readable JSON summary at `$REPORT_DIR/<name>-<timestamp>.json`
(for CI consumption / diffing against the previous run).

**Exit code contract** (important — makes this usable as a CI/pre-commit
gate, not just a cron tool): `repo-health scan <name>` exits non-zero if
any finding is HIGH or CRITICAL severity. Exit 0 otherwise, even with
lower-severity findings.

**Diff-based notification**: when run via `scan --all` from cron, only
notify about NEW findings not present in the previous run's JSON for that
target (compare by CVE/finding ID). Avoids nightly notification fatigue
for known, unfixed issues. Always write the full report either way.

## Health-ping behavior (the "ping" subcommand)

For each ping-mode (or both-mode) target, GET the configured health URL
and classify the response using this detection order:

1. **This project's own "fleet contract" shape** (documented precedent:
   the author's own apps use this): a JSON body shaped like
   `{status, timestamp, checks: {<name>: {status, critical, latency_ms,
   message, short_summary, meta}}}` where `status` is one of
   `ok|degraded|down`. If `checks` is present and any entry has
   `critical: true` and `status: "down"`, treat the whole target as DOWN
   regardless of the top-level status field (defensive — don't trust a
   possibly-stale aggregate).
2. **IETF draft health-check format** (`draft-inadarei-api-health-check`,
   often served as `Content-Type: application/health+json`): JSON body
   shaped like `{status: "pass"|"fail"|"warn", checks: {...}}`. Map
   pass->ok, warn->degraded, fail->down.
3. **Custom override**: if the target config sets
   `HEALTH_STATUS_JSONPATH`, extract that field from the JSON body and use
   it directly as the status string (any truthy/"ok"/"pass"/"up"-like
   value is healthy — document the exact matching rule in the README).
4. **Generic fallback**: any 2xx HTTP response with no recognizable JSON
   shape = healthy (liveness-only, e.g. a bare `/up` with just
   `{"status":"ok"}` or even an empty 200). Any non-2xx or
   connect/timeout failure = DOWN.

If `HEALTH_AUTH_HEADER` is set for a target, send that header (value is
read from an environment variable named in the config, NEVER stored
in plaintext in the target file itself — document this clearly).

Notify immediately on any DOWN or newly-DEGRADED result. Don't notify
repeatedly for a state that hasn't changed since the last ping (track
last-known-status per target in a local state file next to the target
conf, e.g. `targets.d/<name>.state`).

## Notification channels (lib/notify.sh)

One function per channel, all called the same way:
`notify "<subject>" "<body>"` — dispatches based on `$NOTIFY_CHANNEL`.

Implement these channels:
- **ntfy** — `curl -d "$body" -H "Title: $subject" https://ntfy.sh/$NOTIFY_TARGET`
  (default/recommended — zero signup, zero account, topic name is the only
  config value needed)
- **webhook** — raw `curl -X POST -H 'Content-Type: application/json' -d
  '{"subject":...,"body":...}' $NOTIFY_TARGET` — universal escape hatch
  for Zapier/n8n/Make/anything that accepts a POST
- **slack** — Slack incoming-webhook JSON shape (`{"text": "..."}`) to
  `$NOTIFY_TARGET` (the webhook URL)
- **discord** — Discord webhook JSON shape (`{"content": "..."}`) to
  `$NOTIFY_TARGET`
- **telegram** — `https://api.telegram.org/bot<token>/sendMessage` where
  `$NOTIFY_TARGET` is `<bot_token>:<chat_id>` (split on last `:`)
- **pushover** — POST to `api.pushover.net` with
  `$NOTIFY_TARGET` as `<app_token>:<user_key>`
- **email** — uses local `sendmail`/`mail` command if present,
  `$NOTIFY_TARGET` is the recipient address
- **exec** — runs `$NOTIFY_TARGET` (a path to a user script) with subject
  and body as argv — ultimate fallback for anything not listed (SMS,
  PagerDuty, custom webhook auth schemes, etc.)

`repo-health notify-test` must send a real test message through whichever
channel is configured, so setup can be verified in one command.

## `repo-health init` wizard flow

1. Check for an existing `repo-health.conf` — if found, confirm before
   overwriting.
2. Print a numbered list of notify channels (ntfy first/recommended, with
   a one-line description of what config value each needs).
3. Prompt for the channel choice, then prompt for that channel's one
   config value (give a concrete example in the prompt, e.g. for ntfy:
   "Pick any topic name, e.g. 'joes-repo-health-7x2f' — more random is
   better since ntfy topics are not access-controlled by default").
4. Write `repo-health.conf` (mode 600).
5. Run `repo-health doctor` automatically at the end of init.
6. Ask if the user wants to add a target right now; if yes, run through
   `add` interactively (prompt for path or URL). If no, print the exact
   `repo-health add ...` command they can run later.
7. Print (don't install) two example cron lines:
   `0 2 * * * /path/to/repo-health scan --all   # nightly, staggered per install`
   `*/5 * * * * /path/to/repo-health ping --all # every 5 min`
   and tell the user to add them with `crontab -e` themselves.

## `repo-health doctor`

Checks for: `trivy`, `semgrep`, `composer`, `npm`, `pip-audit`, `curl`,
`jq` (needed for JSON parsing — check if present; if not, note that a
pure-bash/grep fallback is used for simple shapes but jq is recommended).
For each missing tool, print the install command for apt (Debian/Ubuntu),
brew (macOS), and a manual/docs link, so it works regardless of the
user's OS. Never auto-installs anything requiring sudo without asking.

## README.md requirements (detailed — this is a deliverable, not optional)

Must include, in this order:
1. One-paragraph pitch: what it replaces (paid rate-limited SaaS scanners
   + a generic uptime monitor), why it's free/unlimited, who it's for.
2. Quick start: install.sh, `repo-health init`, `repo-health doctor`,
   `repo-health add .`, `repo-health scan --all` — a working example in
   under 10 lines.
3. Full subcommand reference (table, one row per subcommand).
4. Full config file reference (global + per-target), with every field
   documented and an example value.
5. Notification channel setup instructions, ONE subsection per channel,
   with exact steps to get the one config value each needs (e.g. exact
   ntfy.sh URL format, exact Slack "create an incoming webhook" link,
   exact Telegram "message @BotFather" steps).
6. Health-endpoint format section: explain the three detected shapes
   (fleet contract / IETF draft / generic) with a JSON example of each,
   and how to use `HEALTH_STATUS_JSONPATH` for anything else.
7. Cron/scheduling recommendations section explaining WHY scan and ping
   have different cadences (cost/frequency tradeoff — dependency scans
   don't find anything new between pushes/CVE disclosures; health pings
   are near-free and should run often), with the two example cron lines.
8. CI usage section: show a GitHub Actions snippet running
   `repo-health scan .` as a job step and failing the build on non-zero
   exit.
9. Supported stacks section: explicit list of what trivy/semgrep/native
   audits cover (npm/yarn/pnpm, composer, pip/poetry/pipenv, go.mod,
   cargo, Maven/Gradle, NuGet, Dockerfile/compose, Terraform/IaC).
10. Platform support: Linux/macOS native, Windows via WSL or Git Bash.
11. Security/privacy note: everything runs locally, no telemetry, no
    data leaves the machine except to the user's own configured
    notification endpoint; secrets (tokens) live in gitignored config
    files, never in the committed repo.
12. License (MIT) and contribution note.

## Testing expectations before calling this done

- `repo-health init` runs end-to-end non-interactively is hard to test,
  but `repo-health doctor`, `repo-health add <this-repo-itself>`,
  `repo-health list`, `repo-health scan --all`, and `repo-health
  notify-test` (using the `exec` channel pointed at a script that just
  echoes args, so no real external account is needed for the smoke test)
  must all be run and shown to work against this repo-health repo itself
  as the test target.
- Markdown report and JSON report must both be produced by a scan run.
- `repo-health scan` must exit non-zero when trivy reports a HIGH/CRITICAL
  finding (can verify logically even if this repo itself has no
  vulnerable deps — check the exit-code logic path exists and is wired
  to trivy's/semgrep's own severity output, not just always-zero).

## Out of scope for this build (don't do these)

- No GUI/dashboard — CLI + markdown/JSON reports only.
- No database — flat files only (targets.d/*.conf, state files, reports).
- No auto-install of anything requiring sudo — doctor only prints the
  command, init/doctor never run sudo themselves.
- No attempt to publish to the Hermes plugin catalog in this build step
  — that's a separate follow-up once this standalone repo exists and is
  pushed to GitHub.
