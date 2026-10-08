# repo-health

**repo-health** is a free, stack-agnostic CLI that does two jobs: it scans any
git repo for vulnerable dependencies, leaked secrets, insecure IaC and risky
code, and it monitors HTTP health-check endpoints and alerts you when a service
goes down. It replaces paid, rate-limited SaaS scanners plus a generic uptime
monitor. Everything runs locally on open-source scanners (trivy, semgrep, and
your package manager's own audit command), so there are no test limits, no
accounts and no credit card. It's for solo developers, small teams and
self-hosters who want "is my code safe and is my service up?" answered every
night and every five minutes, on any stack, with alerts going wherever they
already look.

## Quick start

```bash
git clone https://github.com/Gens-ai/repo-health.git && cd repo-health
./install.sh               # checks/fetches trivy, offers semgrep, links repo-health into ~/.local/bin
repo-health init           # pick a notification channel (ntfy needs no signup)
repo-health doctor         # see which scanners are installed
repo-health add .          # register a repo (here: repo-health itself)
repo-health scan --all     # scan every registered repo; reports land in ~/security-scans
```

The first trivy run downloads its vulnerability database (a few hundred MB),
so it takes a minute. Later runs are fast.

## Setting up the crons

Scans and pings have very different costs, so they run on different schedules:

- **Dependency/code scans are expensive and change slowly.** A scan reads every
  lockfile, runs several scanners and checks large vulnerability databases. Its
  results only change when you push code or a new CVE is published, so
  scanning every few minutes finds nothing new. **Nightly** is right. With
  `scan --all`, you're only notified about **new** findings compared with the
  previous run's JSON report (matched by tool, finding/CVE ID, location and
  package), so a known, unfixed issue doesn't wake you every night. The full
  report is still written every time.
- **Health pings are nearly free** (one HTTP GET) and outages matter within
  minutes, so run them **often**: every 1–5 minutes.

Run `crontab -e` and add (`repo-health init` prints these with your real path
and a per-install staggered scan time, so many installs don't hit vulnerability
databases at exactly the same moment):

```cron
0 2 * * * /path/to/repo-health scan --all   # nightly, staggered per install
*/5 * * * * /path/to/repo-health ping --all # every 5 min
```

Cron has a minimal environment. If trivy/semgrep live in `~/.local/bin`, add a
`PATH=...` line at the top of your crontab. If you use `HEALTH_AUTH_HEADER`,
define those variables there too. Each run appends a one-line summary to
`repo-health.log` in the repo-health home directory.

## Subcommand reference

| Command | What it does |
|---|---|
| `repo-health init` | One-time wizard: pick a notification channel, enter its config value, write `repo-health.conf` (mode 600), run `doctor`, optionally add a first target, print example cron lines. |
| `repo-health doctor` | Checks for `curl`, `jq`, `git`, `trivy`, `semgrep`, `composer`, `npm` and `pip-audit`, and prints the apt, brew and manual install command for each missing one. Also checks your config, targets and report dir. Never installs anything. |
| `repo-health add <path>` | Registers a local repo for scanning. Detects its stack and writes `targets.d/<name>.conf`. Add `--url <health-url>` to also health-ping it (mode `both`). |
| `repo-health add --git <url> [--name X]` | Shallow-clones the repo into `cache/<name>` and registers it. The clone is refreshed (`fetch --depth 1` + hard reset) before every scan. |
| `repo-health add --url <health-url> [--name X]` | Registers a health-ping-only target with no repo and no scanning. |
| `repo-health list` | Table of registered targets: name, mode (`scan`/`ping`/`both`), path/URL. |
| `repo-health remove <name>` | Unregisters a target and deletes its state file, plus its cached clone if repo-health created one. Reports are kept. |
| `repo-health edit <name>` | Opens `targets.d/<name>.conf` in `$VISUAL`/`$EDITOR` (falls back to `vi`), then validates it. |
| `repo-health scan [<name>\|<path>\|--all]` | Runs the dependency/code scan and writes a markdown and a JSON report. **Exits 1 if any HIGH or CRITICAL finding exists**, 0 otherwise, 2 on errors. `--all` (the default with no argument) notifies only about new findings. A bare directory path is scanned ad hoc without registering it, which is handy in CI. |
| `repo-health ping [<name>\|--all]` | Checks health endpoints (`--all` is the default). Notifies when a target goes DOWN, goes DEGRADED, or recovers. Exits 1 if any target is DOWN. |
| `repo-health notify-test` | Sends a real test message through the configured channel. |
| `repo-health version` / `help` | Prints the version / usage. |

Extra options:

- `add`: `--name X`, `--jsonpath .data.ok`, `--auth-header "X-Health-Token: MY_ENV_VAR"`, `--force` (replace an existing target / re-clone).
- `scan`: `--notify` (send the new-findings notification for a single target too), `--no-notify`, `--report-dir DIR`.

Exit codes: `0` OK, `1` HIGH/CRITICAL findings (scan) or a DOWN target (ping), `2` usage/config error.

## Configuration reference

repo-health stores all of its state as flat files next to the install (or under
`$REPO_HEALTH_HOME` if you set it). Config files are **parsed as `KEY=value`
lines, never executed as shell**. Values may be bare, `"double-quoted"` or
`'single-quoted'`. A `#` starts a comment at the start of a line or after
whitespace. A leading `~` expands to your home directory.

| Environment variable | Default | Purpose |
|---|---|---|
| `REPO_HEALTH_HOME` | the repo-health checkout | Where `repo-health.conf`, `targets.d/`, `cache/` and `repo-health.log` live. |
| `REPO_HEALTH_CONF` | `$REPO_HEALTH_HOME/repo-health.conf` | Use a different global config file. |
| `NO_COLOR` | unset | Disable colored output. |

### Global config: `repo-health.conf` (mode 600, gitignored)

`repo-health init` writes it; `repo-health.conf.example` is a commented template.

| Field | Example | Description |
|---|---|---|
| `NOTIFY_CHANNEL` | `ntfy` | One of `ntfy`, `webhook`, `slack`, `discord`, `telegram`, `pushover`, `email`, `exec`. Leave it empty to disable notifications. |
| `NOTIFY_TARGET` | `joes-repo-health-7x2f` | The channel's single config value (see [Notification channels](#notification-channels)). |
| `REPORT_DIR` | `~/security-scans` | Where `<name>-<timestamp>.md` and `.json` reports are written (created with mode 700). |
| `SEMGREP_CONFIG` | `auto` | Optional. The semgrep ruleset. `auto` requires semgrep's anonymous metrics; any other value (e.g. `p/default`, `p/owasp-top-ten`, or a local rules file) runs with `--metrics off`. |
| `PING_TIMEOUT` | `10` | Optional. Seconds before a health ping counts as DOWN. |

### Per-target config: `targets.d/<name>.conf` (mode 600, gitignored)

`repo-health add` writes it; `repo-health edit <name>` changes it. Because each
target is its own file, you can add or remove repos at any time without
re-running setup or editing a shared list. Config management tools can also
drop files into `targets.d/` directly.

| Field | Example | Description |
|---|---|---|
| `NAME` | `upwork-prospects` | Target name (letters, digits, `.`, `_`, `-`). It matches the file name. |
| `MODE` | `scan` | `scan` (dependency/code scan), `ping` (health check) or `both`. |
| `PATH` | `/var/www/upwork-prospects` | Repo directory to scan (scan/both). Never confused with your shell's `$PATH`, because the file is parsed, not sourced. |
| `HEALTH_URL` | `https://example.com/up` | Endpoint to GET (ping/both). |
| `HEALTH_STATUS_JSONPATH` | `.data.ok` | Optional. A jq path to the status field for custom JSON shapes (see [Custom shapes](#anything-else-health_status_jsonpath)). |
| `HEALTH_AUTH_HEADER` | `X-Health-Token: UPWORK_HEALTH_TOKEN` | Optional. `Header-Name: ENV_VAR_NAME`. The part after the colon is the **name of an environment variable**; at ping time repo-health reads that variable and sends its value as the header. The secret itself is never written to the target file. repo-health passes it to curl through a temporary mode-600 file, so it never shows up in `ps`. If the variable is unset, the target is reported DOWN with a clear message. With cron, define the variable at the top of your crontab or in a wrapper script. |
| `GIT_URL` | `https://github.com/you/app.git` | Set by `add --git`. When set, and `PATH` is repo-health's own cache clone, the clone is refreshed before each scan. |

A third kind of file, `targets.d/<name>.state`, is written by `ping` to remember
the last known status. Don't edit it.

## Notification channels

All channels are called the same way internally (`notify "<subject>" "<body>"`)
and each one needs exactly **one** value in `NOTIFY_TARGET`. Run
`repo-health notify-test` after setting one up.

### ntfy (default, recommended: no signup at all)

1. Pick a hard-to-guess topic name, e.g. `joes-repo-health-7x2f`. Anyone who
   knows a public ntfy topic can read it, so make it random.
2. Install the ntfy app ([Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy),
   [iOS](https://apps.apple.com/app/ntfy/id1625396347)), or open
   `https://ntfy.sh/<your-topic>` in a browser, and subscribe to that topic.
3. Set:
   ```
   NOTIFY_CHANNEL=ntfy
   NOTIFY_TARGET=joes-repo-health-7x2f
   ```
   Messages are POSTed to `https://ntfy.sh/<topic>` with the subject as the
   `Title` header. To use a self-hosted server, put the full URL in
   `NOTIFY_TARGET`, e.g. `https://ntfy.example.com/repo-health`.

### webhook (Zapier, n8n, Make, Home Assistant, anything)

1. Create a "catch webhook" / "webhook trigger" in your automation tool and
   copy its URL.
2. Set `NOTIFY_CHANNEL=webhook` and `NOTIFY_TARGET=<that URL>`.

repo-health POSTs `Content-Type: application/json` with the body
`{"subject": "...", "body": "..."}`.

### slack

1. Go to <https://api.slack.com/apps?new_app=1> → **From scratch**, pick your workspace.
2. Under **Incoming Webhooks**, toggle it on → **Add New Webhook to Workspace** → choose a channel.
   (Docs: <https://api.slack.com/messaging/webhooks>.)
3. Copy the URL (`https://hooks.slack.com/services/T…/B…/…`) and set
   `NOTIFY_CHANNEL=slack`, `NOTIFY_TARGET=<that URL>`.

### discord

1. In Discord: **Server Settings → Integrations → Webhooks → New Webhook**, pick a channel.
2. **Copy Webhook URL** (`https://discord.com/api/webhooks/<id>/<token>`).
3. Set `NOTIFY_CHANNEL=discord`, `NOTIFY_TARGET=<that URL>`. (Messages are cut to Discord's 2000-character limit.)

### telegram

1. In Telegram, message **@BotFather**, send `/newbot`, and follow the prompts.
   It replies with a bot token shaped like `<digits>:<letters-and-digits>`.
2. Open a chat with your new bot and send it any message (bots can't message
   you first). For a group, add the bot to the group and post a message there.
3. Get your chat id: open `https://api.telegram.org/bot<token>/getUpdates` in a
   browser and find `"chat":{"id": ...}`. Group ids are negative, e.g. `-1001234567890`.
4. Set `NOTIFY_CHANNEL=telegram` and `NOTIFY_TARGET=<bot_token>:<chat_id>`. The
   token itself contains a colon, so repo-health splits on the **last** colon.

### pushover

1. Sign in at <https://pushover.net/> (a one-time purchase per platform after a
   30-day free trial). Your **User Key** is on the dashboard.
2. Create an application at <https://pushover.net/apps/build> to get an **API Token**.
3. Set `NOTIFY_CHANNEL=pushover` and `NOTIFY_TARGET=<app_token>:<user_key>`.
   DOWN alerts are sent with high priority.

### email

Uses the machine's own `sendmail` (Postfix, msmtp-mta, ssmtp, …) or `mail`
command, so nothing goes through a third-party API.

1. Make sure one of them works: `echo test | mail -s test you@example.com`.
   On Debian/Ubuntu `sudo apt-get install -y msmtp-mta` (relay through any SMTP
   account) or `mailutils`; on macOS, `mail` is built in but needs a configured relay.
2. Set `NOTIFY_CHANNEL=email` and `NOTIFY_TARGET=you@example.com`.

### exec (anything else: SMS, PagerDuty, custom auth…)

1. Write an executable script that takes the subject as `$1` and the body as `$2`:
   ```bash
   #!/usr/bin/env bash
   # ~/bin/repo-health-alert.sh
   printf '%s\n%s\n' "$1" "$2" | logger -t repo-health
   ```
2. `chmod +x ~/bin/repo-health-alert.sh`, then set `NOTIFY_CHANNEL=exec` and
   `NOTIFY_TARGET=/home/you/bin/repo-health-alert.sh`.

A non-zero exit from your script counts as a failed delivery.

## Health-endpoint formats

`repo-health ping` GETs `HEALTH_URL` (following redirects, sending
`Accept: application/health+json, application/json`) and classifies the
result as **OK**, **DEGRADED** or **DOWN**. **Any non-2xx response, connection
error or timeout is DOWN**, whatever the body says. For 2xx responses, the body
is checked in this order:

1. If `HEALTH_STATUS_JSONPATH` is set, that field decides (an explicit override always wins).
2. Fleet contract shape.
3. IETF health-check draft shape.
4. Generic fallback.

### 1. Fleet contract

Detected when top-level `status` is `ok`, `degraded` or `down` **and**
`checks` is an object.

```json
{
  "status": "ok",
  "timestamp": "2026-10-08T12:00:00Z",
  "checks": {
    "database": {"status": "ok",   "critical": true,  "latency_ms": 3,   "message": "connected", "short_summary": "db ok", "meta": {}},
    "queue":    {"status": "down", "critical": false, "latency_ms": 0,   "message": "redis timeout", "short_summary": "queue down", "meta": {}}
  }
}
```

The status maps as `ok`→OK, `degraded`→DEGRADED, `down`→DOWN. As a defensive
rule, **if any check has `"critical": true` and `"status": "down"`, the target
is DOWN even if the top-level status still says `ok`**, because an aggregate
can be stale. Non-ok checks are listed in the alert detail. (This override
needs jq; without jq only the top-level status is read.)

### 2. IETF health-check draft (`draft-inadarei-api-health-check`)

Detected when `status` is `pass`, `warn` or `fail`, or when the response is
`Content-Type: application/health+json`.

```json
{
  "status": "warn",
  "version": "1",
  "output": "disk filling up",
  "checks": {
    "disk:utilization": [{"status": "warn", "observedValue": 91, "observedUnit": "percent"}],
    "postgres:responseTime": [{"status": "pass", "observedValue": 12, "observedUnit": "ms"}]
  }
}
```

`pass`→OK, `warn`→DEGRADED, `fail`→DOWN. The draft's aliases `ok`/`up` map to OK
and `error`/`down` map to DOWN. Failing and warning checks are listed in the
alert detail.

### 3. Generic fallback (liveness only)

Any other 2xx response is **healthy**. That includes an empty `200`, plain
text, or a bare `{"status": "ok"}`:

```json
{"status": "ok"}
```

One safety net applies: if a 2xx JSON body has a top-level `status` string of
`down`, `fail`, `failed`, `failing`, `error`, `unhealthy`, `critical`, `red` or
`false`, it's treated as DOWN. `warn`, `warning`, `degraded`, `partial` and
`yellow` are treated as DEGRADED. Any other value is OK, so Spring Boot's
`{"status":"UP"}` works out of the box.

### Anything else: `HEALTH_STATUS_JSONPATH`

For any other shape, point repo-health at the field that holds the status, using a
[jq](https://jqlang.org/manual/) path:

```json
{"data": {"ok": true, "uptime": 12345}}
```

```
HEALTH_STATUS_JSONPATH=.data.ok
```

**Exact matching rule.** The extracted value is lowercased and trimmed of
whitespace and quotes, then:

| Value | Result |
|---|---|
| `ok`, `pass`, `passed`, `passing`, `up`, `healthy`, `true`, `yes`, `on`, `green`, `success`, `good`, `alive`, `ready`, `running`, `1` | **OK** |
| `warn`, `warning`, `degraded`, `partial`, `yellow` | **DEGRADED** |
| anything else, including `false`, `0`, `null`, a missing field, `down`, `fail` | **DOWN** |

Without jq, a grep fallback matches only the **last segment** of the path
(`ok` in `.data.ok`) wherever it first appears in the body, so install jq for
nested or ambiguous shapes.

### When you get notified

Notifications are sent only when the status changes: into **DOWN**, into
**DEGRADED**, and on **recovery** back to OK. A service that stays down for
an hour sends one alert, not twelve. State is kept in `targets.d/<name>.state`.
If a notification fails to send, the state change isn't recorded, so the
next ping retries the alert.

## CI usage

`repo-health scan <path>` works without registering a target or running
`init`, and it exits non-zero on any HIGH/CRITICAL finding, so it works as a
build gate. GitHub Actions example:

```yaml
name: security
on: [push, pull_request]

jobs:
  repo-health:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install trivy
        run: |
          curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b "$HOME/.local/bin"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Get repo-health
        run: git clone --depth 1 https://github.com/Gens-ai/repo-health.git "$RUNNER_TEMP/repo-health"

      - name: Scan (fails the build on HIGH/CRITICAL)
        run: |
          export REPO_HEALTH_HOME="$RUNNER_TEMP/rh-home"
          "$RUNNER_TEMP/repo-health/bin/repo-health" scan . --report-dir "$RUNNER_TEMP/reports"

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: repo-health-reports
          path: ${{ runner.temp }}/reports/
```

The step fails when `repo-health scan` exits `1`. The JSON report
(`counts`, `findings[]`, `exit_code`) is easy to post-process with jq. To
accept a known finding, add its ID to a `.trivyignore` file in the repo root,
and repo-health passes that file to trivy automatically.

## Supported stacks

| Ecosystem / artifact | Covered by |
|---|---|
| npm / yarn / pnpm (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) | trivy, plus `npm audit --omit=dev` when `package.json` exists |
| Composer (`composer.lock`) | trivy, plus `composer audit` when `composer.json` exists |
| pip / poetry / pipenv / uv (`requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`) | trivy, plus `pip-audit -r requirements.txt` when `requirements.txt` exists |
| Go (`go.mod`) | trivy |
| Rust / Cargo (`Cargo.lock`) | trivy |
| Java: Maven / Gradle (`pom.xml`, `gradle.lockfile`) | trivy |
| .NET / NuGet (`packages.lock.json`, `*.deps.json`, `packages.config`) | trivy |
| Ruby, Dart, Elixir, Swift, Conan lockfiles | trivy |
| Dockerfile / docker-compose | trivy misconfig (`trivy fs`, plus `trivy config` when such files exist) |
| Terraform, CloudFormation, Kubernetes YAML, Helm | trivy misconfig |
| Hard-coded secrets (API keys, tokens, private keys) in any file | trivy secret scanner |
| Source code bugs and insecure patterns (Python, JS/TS, Go, Java, PHP, Ruby, C#, Kotlin, and more) | semgrep (`--config auto`) |

trivy reports HIGH and CRITICAL issues only. semgrep reports ERROR (counted as
HIGH) and WARNING (counted as MEDIUM). Native audits report what the package
manager says. pip-audit advisories carry no severity, so they're reported as
UNKNOWN and don't fail the scan.

## Platform support

- **Linux and macOS:** native. Needs bash 3.2+ (the stock macOS bash works),
  curl and standard POSIX tools; jq is recommended.
- **Windows:** use **WSL** (recommended: install Ubuntu from the Microsoft
  Store and follow the Linux instructions) or **Git Bash** (bash, curl and git
  are included; install trivy's Windows binary and put it on your `PATH`).
  Native PowerShell/cmd isn't supported. Scheduling under Git Bash means Task
  Scheduler calling `bash.exe -lc "repo-health ping --all"`, rather than cron.

## Security and privacy

- **Everything runs locally.** repo-health has no server, no account and no
  telemetry. The only data that leaves your machine is what you send to your
  own notification endpoint, plus the scanners' own downloads: trivy fetches
  its vulnerability database, npm/composer/pip-audit query their registries'
  advisory APIs, and semgrep `--config auto` fetches rules and sends semgrep's
  anonymous usage metrics. Set `SEMGREP_CONFIG` to a specific ruleset to run
  semgrep with `--metrics off`.
- **Secrets stay out of git.** Tokens live only in `repo-health.conf` and
  `targets.d/*.conf`. Both are gitignored and written with mode 600, and
  `doctor` warns if the global config is readable by others. Health-check auth
  values aren't stored at all, only the name of the environment variable that
  holds them.
- **Config is data, not code.** Config files are parsed, never `source`d.
- **Nothing escalates.** repo-health never runs `sudo`. `doctor` and
  `install.sh` print commands that need root for you to run yourself.
- Reports can contain sensitive detail (e.g. where a secret was found), so
  they're written with mode 600 in a mode-700 directory.

## License and contributing

MIT. See [LICENSE](LICENSE).

Contributions are welcome. Open an issue or a pull request at
<https://github.com/Gens-ai/repo-health>. Please keep the core in bash plus
POSIX tools (no new language runtimes), keep every bundled scanner and notifier
usable without a paid account, and run `bash -n` (and `shellcheck` if you have
it) on changed scripts. New notification channels are a single `notify_<name>`
function in `lib/notify.sh`.
