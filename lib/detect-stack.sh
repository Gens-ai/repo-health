# shellcheck shell=bash
# lib/detect-stack.sh — figure out what ecosystems a repo uses.
#
# Detection is informational (shown by `add` and in reports) and also decides
# which supplementary native audits / trivy config scans are worth running.

# _rh_manifest_files <dir> — basenames of files up to 3 levels deep, skipping
# vendored/build directories that would only add noise.
_rh_manifest_files() {
  find "$1" -maxdepth 3 \
    \( -name node_modules -o -name vendor -o -name .git -o -name .venv -o -name venv \
       -o -name __pycache__ -o -name target -o -name dist -o -name build \
       -o -path "${RH_CACHE:-/nonexistent}" \) -prune \
    -o -type f -print 2>/dev/null | sed 's|.*/||' | sort -u
}

# rh_detect_stack <dir> — print a space-separated list of detected stacks.
rh_detect_stack() {
  local files out=""
  files=$(_rh_manifest_files "$1")
  _has() { printf '%s\n' "$files" | grep -Eq -- "$1"; }

  _has '^(package\.json|package-lock\.json)$'                 && out="$out npm"
  _has '^yarn\.lock$'                                         && out="$out yarn"
  _has '^pnpm-lock\.yaml$'                                    && out="$out pnpm"
  _has '^bun\.lockb?$'                                        && out="$out bun"
  _has '^composer\.(json|lock)$'                              && out="$out composer"
  _has '^(requirements.*\.txt|setup\.py|setup\.cfg)$'         && out="$out pip"
  _has '^(poetry\.lock|pyproject\.toml)$'                     && out="$out poetry/pyproject"
  _has '^Pipfile(\.lock)?$'                                   && out="$out pipenv"
  _has '^uv\.lock$'                                           && out="$out uv"
  _has '^go\.mod$'                                            && out="$out go"
  _has '^Cargo\.(toml|lock)$'                                 && out="$out cargo"
  _has '^pom\.xml$'                                           && out="$out maven"
  _has '^(build\.gradle(\.kts)?|gradle\.lockfile)$'           && out="$out gradle"
  _has '(\.csproj|^packages\.config|^packages\.lock\.json)$'  && out="$out nuget"
  _has '^Gemfile(\.lock)?$'                                   && out="$out ruby"
  _has '^pubspec\.(yaml|lock)$'                               && out="$out dart"
  _has '^mix\.(exs|lock)$'                                    && out="$out elixir"
  _has '^Package\.(swift|resolved)$'                          && out="$out swift"
  _has '^(Dockerfile.*|.*\.Dockerfile|(docker-)?compose.*\.ya?ml)$' && out="$out docker"
  _has '\.tf$'                                                && out="$out terraform"
  _has '^Chart\.yaml$'                                        && out="$out helm"

  unset -f _has
  printf '%s' "${out# }"
}

# rh_has_container_files <dir> — true if a Dockerfile or compose file exists.
rh_has_container_files() {
  _rh_manifest_files "$1" | grep -Eq '^(Dockerfile.*|.*\.Dockerfile|(docker-)?compose.*\.ya?ml)$'
}
