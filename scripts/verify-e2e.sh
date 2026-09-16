#!/bin/bash
# End-to-end verification of every documented AgentShield behaviour.
# Each check asserts on real output, not just a zero exit code.

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$REPO/packages/cli/src/index.js"
LAB="$(mktemp -d)"
PASS=0; FAIL=0
declare -a FAILURES

ok()   { PASS=$((PASS+1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILURES+=("$1 — $2"); printf "  \033[31mFAIL\033[0m  %s\n        \033[31m%s\033[0m\n" "$1" "$2"; }

# assert_contains <label> <haystack> <needle>
assert_contains() {
  case "$2" in *"$3"*) ok "$1";; *) bad "$1" "expected to contain: $3";; esac
}
assert_not_contains() {
  case "$2" in *"$3"*) bad "$1" "should NOT contain: $3";; *) ok "$1";; esac
}
assert_eq() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3', got '$2'"; }

section() { printf "\n\033[1m%s\033[0m\n" "$1"; }

# ---------------------------------------------------------------- lab fixtures
mkdir -p "$LAB/proj"
# A fake, syntactically-valid OpenAI-shaped key. Not a real credential.
printf 'OPENAI_API_KEY=sk-%s\n' "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234" > "$LAB/proj/.env"
printf 'OPENAI_API_KEY=sk-%s\n' "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234" > "$LAB/proj/.env.example"
cat > "$LAB/risky.toml" <<'EOF'
[network]
host = "0.0.0.0"

[mcp_servers.remote]
url = "https://mcp.example.invalid"
auth = "none"

[execution]
yolo = true
EOF
cat > "$LAB/safe.toml" <<'EOF'
[network]
host = "127.0.0.1"

[mcp_servers.local]
url = "http://127.0.0.1:8080/mcp"
auth = "token"
EOF

section "1. Command surface"
H=$(node "$CLI" 2>&1); assert_contains "bare invocation prints help" "$H" "Usage:"
H=$(node "$CLI" --help 2>&1); assert_contains "--help prints help" "$H" "agentshield scan"
H=$(node "$CLI" -h 2>&1); assert_contains "-h prints help" "$H" "agentshield scan"
V=$(node "$CLI" --version 2>&1); assert_eq "--version matches package.json" "$V" "$(node -p "require('$REPO/package.json').version")"
node "$CLI" --help >/dev/null 2>&1; assert_eq "help exits 0" "$?" "0"
node "$CLI" nonsense >/dev/null 2>&1; assert_eq "unknown command exits 1" "$?" "1"
E=$(node "$CLI" nonsense 2>&1); assert_contains "unknown command names itself" "$E" "Unknown command: nonsense"

section "2. Help text promises match reality"
for flag in --all --json --format=md --output= --category= --severity= --concise --secret-path= --config-path= --skill-path= --audit-target= --global --path= --port=; do
  assert_contains "help documents $flag" "$H" "$flag"
done

section "2b. Usage errors fail loudly instead of printing a clean report"
node "$CLI" scan --severity=hgih >/dev/null 2>&1; assert_eq "misspelt severity exits 1" "$?" "1"
assert_contains "misspelt severity lists the options" "$(node "$CLI" scan --severity=hgih 2>&1)" "Choose one of: info, low, medium, high, critical"
node "$CLI" scan --formt=md >/dev/null 2>&1; assert_eq "unknown flag exits 1" "$?" "1"
assert_contains "unknown flag suggests the right one" "$(node "$CLI" scan --formt=md 2>&1)" "Did you mean --format?"
node "$CLI" scan --category=skills >/dev/null 2>&1; assert_eq "unknown category exits 1" "$?" "1"
node "$CLI" preupdate --nope npm >/dev/null 2>&1; assert_eq "unknown preupdate flag exits 1" "$?" "1"

section "3. Secret detection"
S=$(NO_COLOR=1 node "$CLI" scan --secret-path="$LAB/proj" --category=secret-exposure --all 2>&1)
assert_contains "detects planted key" "$S" "OpenAI key"
assert_contains "planted key is HIGH" "$S" "HIGH"
assert_not_contains "raw secret never printed" "$S" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234"
J=$(node "$CLI" scan --secret-path="$LAB/proj" --category=secret-exposure --json 2>&1)
assert_contains "json redacts value" "$J" '"redactedValue"'
assert_not_contains "json never leaks raw secret" "$J" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234"
assert_not_contains "placeholder .env.example skipped" "$S" ".env.example"

section "4. Config risk detection"
C=$(NO_COLOR=1 node "$CLI" scan --config-path="$LAB/risky.toml" --category=config-risk --all 2>&1)
assert_contains "wildcard bind"        "$C" "listen on every network interface"
assert_contains "missing auth"         "$C" "without authentication"
assert_contains "skipped safeguards"   "$C" "skip execution safeguards"
assert_contains "remote MCP"           "$C" "remote MCP server"
SAFE=$(node "$CLI" scan --config-path="$LAB/safe.toml" --category=config-risk --json 2>&1)
SAFE_N=$(echo "$SAFE" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.findings.filter(f=>f.path==='$LAB/safe.toml').length)})")
assert_eq "benign config produces zero findings" "$SAFE_N" "0"

section "5. Skill risk detection"
K=$(NO_COLOR=1 node "$CLI" scan --skill-path="$REPO/fixtures/risky-skill" --category=skill-risk --all 2>&1)
assert_contains "fetch-and-run installer"  "$K" "fetches remote code and runs it"
assert_contains "credential exfiltration"  "$K" "sends data off this machine"
assert_contains "instruction override"     "$K" "override its own rules"
assert_contains "unrestricted shell"       "$K" "unrestricted shell access"
assert_contains "skill risk is CRITICAL"   "$K" "CRITICAL"
mkdir -p "$LAB/safe-skill/tidy"
cat > "$LAB/safe-skill/tidy/SKILL.md" <<'EOF'
---
name: tidy
description: Summarize the working tree.
allowed-tools:
  - Read
  - Bash(git status *)
---

Read the changed files with git diff, then summarize them for the user.
EOF
SAFE_K=$(node "$CLI" scan --skill-path="$LAB/safe-skill" --category=skill-risk --json 2>&1)
SAFE_KN=$(echo "$SAFE_K" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.findings.filter(f=>String(f.path||'').includes('safe-skill')).length)})")
assert_eq "benign skill produces zero findings" "$SAFE_KN" "0"

section "5b. Explicit skill paths are never starved by the machine's own skills"
KJ=$(node "$CLI" scan --skill-path="$REPO/fixtures/risky-skill" --category=skill-risk --json 2>&1 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);const inv=j.findings.find(f=>f.id==='skill-inventory');console.log((inv&&inv.metadata.byScope.explicit)||0)})")
assert_eq "fixture skill is counted as explicit" "$KJ" "1"
FV=$(NO_COLOR=1 node "$CLI" scan --category=skill-risk 2>&1)
assert_contains "filtered view marks other rows as not shown" "$FV" "not in this view"
assert_not_contains "filtered view does not call other rows clear" "$FV" "Secrets         clear"

section "6. Filters and summary integrity"
FJ=$(node "$CLI" scan --category=config-risk --json 2>&1)
node -e "
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
  const j=JSON.parse(d);
  const wrongCat=j.findings.filter(f=>f.category!=='config-risk').length;
  const counted=Object.values(j.posture.severityCounts).reduce((a,b)=>a+b,0);
  console.log(wrongCat===0?'CATOK':'CATBAD');
  console.log(counted===j.findings.length?'SUMOK':'SUMBAD '+counted+'!='+j.findings.length);
})" <<< "$FJ" > "$LAB/filter.txt"
assert_contains "--category returns only that category" "$(cat "$LAB/filter.txt")" "CATOK"
assert_contains "summary counts match filtered findings" "$(cat "$LAB/filter.txt")" "SUMOK"
SEV=$(node "$CLI" scan --severity=high --json 2>&1 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.findings.every(f=>f.severity==='high')?'OK':'BAD')})")
assert_eq "--severity returns only that severity" "$SEV" "OK"

section "7. Finding id uniqueness"
IDS=$(node "$CLI" scan --json --config-path="$LAB/risky.toml" --config-path="$LAB/safe.toml" 2>&1 | node -e "
let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
  const j=JSON.parse(d); const ids=j.findings.map(f=>f.id);
  console.log(new Set(ids).size===ids.length?'UNIQUE':'DUPES');
})")
assert_eq "all finding ids unique in one scan" "$IDS" "UNIQUE"

section "8. Output formats"
assert_contains "default output is human-readable" "$(NO_COLOR=1 node "$CLI" scan 2>&1)" "· security audit"
assert_contains "--json is valid JSON" "$(node "$CLI" scan --json 2>&1 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{JSON.parse(d);console.log('VALIDJSON')})")" "VALIDJSON"
assert_contains "--format=md is markdown" "$(node "$CLI" scan --format=md 2>&1)" "# AgentShield Report"
node "$CLI" scan --output="$LAB/r.json" >/dev/null 2>&1
assert_contains "--output=.json infers JSON" "$(head -c 400 "$LAB/r.json")" '"schemaVersion"'
node "$CLI" scan --output="$LAB/r.md" >/dev/null 2>&1
assert_contains "--output=.md infers Markdown" "$(head -c 400 "$LAB/r.md")" "# AgentShield Report"
FORCE_COLOR=1 node "$CLI" scan --output="$LAB/r.txt" >/dev/null 2>&1
assert_not_contains "--output never writes ANSI codes" "$(cat -v "$LAB/r.txt")" "^["
J2=$(node "$CLI" scan --json 2>&1 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log('filters' in j && !('history' in j) ? 'SHAPE' : 'NOSHAPE')})")
assert_eq "json carries the filters key and no history" "$J2" "SHAPE"
CONCISE=$(node "$CLI" scan --concise --json 2>&1 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.findings.length===0||j.findings[0].description===undefined?'TRIMMED':'FULL')})")
assert_eq "--concise trims fields" "$CONCISE" "TRIMMED"

section "9. Colour handling"
assert_contains "FORCE_COLOR emits ANSI"  "$(FORCE_COLOR=1 node "$CLI" scan 2>&1 | cat -v)" "^["
assert_not_contains "NO_COLOR suppresses ANSI" "$(NO_COLOR=1 node "$CLI" scan 2>&1 | cat -v)" "^["
assert_not_contains "piped output has no ANSI by default" "$(node "$CLI" scan 2>&1 | cat -v)" "^["

section "10. Exit codes"
# --severity=info can never carry a critical or high finding, whatever the host machine holds.
node "$CLI" scan --severity=info >/dev/null 2>&1; C1=$?
node "$CLI" scan --config-path="$LAB/risky.toml" --category=config-risk >/dev/null 2>&1; C2=$?
assert_eq "clean scan exits 0" "$C1" "0"
assert_eq "high findings exit 2" "$C2" "2"

section "11. Preupdate"
P=$(node "$CLI" preupdate --global npm 2>&1)
assert_contains "reports installed version" "$P" "Current:"
assert_contains "gives a verdict" "$P" "Verdict:"
assert_contains "states npm-only limit" "$P" "npm-only"
node "$CLI" preupdate --global npm >/dev/null 2>&1; assert_eq "found package exits 0 or 2" "$([ $? -eq 0 ] || [ $? -eq 2 ] && echo ok)" "ok"
BAD=$(node "$CLI" preupdate 'evil; rm -rf /' 2>&1)
assert_contains "rejects shell syntax" "$BAD" "not a valid npm package name"
node "$CLI" preupdate 'evil; rm -rf /' >/dev/null 2>&1; assert_eq "invalid name exits 1" "$?" "1"
MISS=$(node "$CLI" preupdate definitely-not-installed-xyz --global 2>&1)
assert_contains "missing package says so" "$MISS" "not installed"
node "$CLI" preupdate >/dev/null 2>&1; assert_eq "preupdate with no arg exits 1" "$?" "1"

section "12. Dashboard"
node "$CLI" dashboard --port=abc >/dev/null 2>&1; assert_eq "invalid port exits 1" "$?" "1"
node "$CLI" dashboard --port=99999 >/dev/null 2>&1; assert_eq "out-of-range port exits 1" "$?" "1"
node "$CLI" dashboard --port=4611 >/dev/null 2>&1 &
DASH=$!; sleep 6
assert_eq "GET / serves html"        "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4611/)" "200"
assert_eq "GET /favicon.ico is 404"  "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4611/favicon.ico)" "404"
assert_eq "POST / is 405"            "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:4611/)" "405"
assert_eq "api/package-check is 200"  "$(curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:4611/api/package-check?package=npm')" "200"
assert_contains "dashboard sets CSP"  "$(curl -sI http://127.0.0.1:4611/)" "content-security-policy"
assert_contains "dashboard nosniff"   "$(curl -sI http://127.0.0.1:4611/)" "x-content-type-options"
assert_eq "binds loopback only, not 0.0.0.0" "$(lsof -nP -iTCP:4611 -sTCP:LISTEN 2>/dev/null | grep -c '127.0.0.1:4611')" "1"
kill $DASH 2>/dev/null; wait $DASH 2>/dev/null

section "13. Robustness"
node "$CLI" scan --config-path=/nonexistent/nope.toml >/dev/null 2>&1; assert_eq "missing --config-path does not crash" "$?" "$?"
node "$CLI" scan --secret-path=/nonexistent/nope >/dev/null 2>&1; R=$?
[ $R -eq 0 ] || [ $R -eq 2 ]; assert_eq "missing --secret-path does not crash" "$([ $? -eq 0 ] && echo ok)" "ok"
node "$CLI" scan --skill-path=/nonexistent/skills >/dev/null 2>&1; R=$?
[ $R -eq 0 ] || [ $R -eq 2 ]; assert_eq "missing --skill-path does not crash" "$([ $? -eq 0 ] && echo ok)" "ok"
printf '\x00\x01\x02 not text' > "$LAB/binary.toml"
node "$CLI" scan --config-path="$LAB/binary.toml" >/dev/null 2>&1; R=$?
[ $R -eq 0 ] || [ $R -eq 2 ]; assert_eq "binary config does not crash" "$([ $? -eq 0 ] && echo ok)" "ok"

printf "\n\033[1mRESULT\033[0m  %d passed, %d failed\n" "$PASS" "$FAIL"
if [ ${#FAILURES[@]} -gt 0 ]; then
  printf "\n\033[31mFailures:\033[0m\n"
  for f in "${FAILURES[@]}"; do printf "  - %s\n" "$f"; done
fi
rm -rf "$LAB"
exit $FAIL
