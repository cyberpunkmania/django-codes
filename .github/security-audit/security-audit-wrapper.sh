#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'Security audit error: %s\n' "$*" >&2; exit 2; }
usage() { fail 'usage: security-audit-wrapper.sh --staged | --full | --range BASE HEAD'; }

mode=${1:-}
case "$mode:$#" in
  --staged:1|--full:1|--range:3) ;;
  *) usage ;;
esac

repo=$(git rev-parse --show-toplevel) || fail 'run from a Git worktree'
policy=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/semgrep-security.yml
cd -- "$repo"
if [[ $mode == --staged ]]; then
  rc=0
  git diff --cached --quiet -- || rc=$?
  [[ $rc != 0 ]] || exit 0
  [[ $rc == 1 ]] || fail 'could not read the Git index'
fi
for tool in git node gitleaks semgrep; do
  command -v "$tool" >/dev/null || fail "$tool is required on PATH"
done
[[ -r $policy ]] || fail "missing policy $policy"
scratch=$(mktemp -d) || fail 'could not create scratch directory'
trap 'rm -rf -- "$scratch"' EXIT
printf '[extend]\nuseDefault = true\n' > "$scratch/gitleaks.toml"
: > "$scratch/.gitleaksignore"

tree=$repo
leaks=(git --staged)
semgrep_args=()
case "$mode" in
  --staged)
    tree=$scratch/staged
    mkdir -- "$tree"
    # Use the index contents even when a partially staged file has unstaged edits.
    git diff --cached --name-only --diff-filter=ACMRT -z -- |
      git checkout-index --stdin -z --prefix="$tree/" ||
      fail 'could not materialize staged paths'
    ;;
  --full) leaks=(dir) ;;
  --range)
    base=$(git rev-parse --verify "$2^{commit}") || fail 'invalid baseline commit'
    head=$(git rev-parse --verify "$3^{commit}") || fail 'invalid head commit'
    [[ $(git rev-parse HEAD) == "$head" ]] || fail 'HEAD must match the scan head'
    leaks=(git "--log-opts=--diff-merges=first-parent $base..$head")
    semgrep_args+=("--baseline-commit=$base")
    ;;
esac

rc=0
gitleaks "${leaks[@]}" --config "$scratch/gitleaks.toml" \
  --gitleaks-ignore-path "$scratch/.gitleaksignore" --ignore-gitleaks-allow \
  --redact=100 --no-banner --exit-code 10 --report-format json \
  --report-path "$scratch/leaks.json" "$repo" >&2 || rc=$?
case "$rc" in
  0|10) ;;
  *) fail "Gitleaks exited $rc" ;;
esac
blocked=0
if [[ $rc == 10 ]]; then
  blocked=1
  node -e '
    const findings = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    if (!Array.isArray(findings) || !findings.length) process.exit(2);
    for (const f of findings) {
      console.error(JSON.stringify(f.File) + ":" + f.StartLine + " BLOCK " + f.RuleID +
        " — Remove the credential, rotate it if exposed, and load it from a secret store.");
    }' "$scratch/leaks.json" || fail 'invalid Gitleaks report'
fi

if [[ $mode != --staged ]] || [[ -n $(find "$tree" -type f -print -quit) ]]; then
  (
    cd -- "$tree"
    semgrep scan --config "$policy" --metrics off --disable-version-check \
      --disable-nosem --strict --json "${semgrep_args[@]}" .
  ) > "$scratch/semgrep.json" || fail 'Semgrep could not complete the scan'
  rc=0
  node -e '
    const report = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
    if (!Array.isArray(report.results) || report.errors?.length) process.exit(2);
    for (const f of report.results) {
      const block = ["ERROR", "HIGH", "CRITICAL"].includes(f.extra.severity) &&
        f.extra.metadata?.confidence === "HIGH";
      console.error(JSON.stringify(f.path) + ":" + f.start.line + " " +
        (block ? "BLOCK " : "WARN ") + f.check_id + " — " + f.extra.message);
      if (block) process.exitCode = 10;
    }' "$scratch/semgrep.json" || rc=$?
  case "$rc" in
    0) ;;
    10) blocked=1 ;;
    *) fail 'invalid Semgrep report' ;;
  esac
fi
exit "$blocked"
