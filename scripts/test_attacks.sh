#!/usr/bin/env bash
#
# ZeroWall - Attack Simulation Script (Phase 5)
#
# Runs all demo scenarios sequentially against the deployed API. Each scenario
# prints the curl command, the expected vs actual status, and PASS/FAIL.
# A summary table is printed at the end.
#
# Requirements:
#   - curl, jq, awscli (configured for us-east-2)
#   - The script promotes one test user to admin via Cognito CLI, then demotes
#     back at the end. AWS CLI creds need cognito-idp:AdminUpdateUserAttributes.
#
# Usage:
#   ./test_attacks.sh                     Run all scenarios
#   ./test_attacks.sh --prep-expired      Capture a token now for use 65+ min later
#   ./test_attacks.sh --help              Print help
#
# Override defaults via env vars:
#   BASE_URL, USER_EMAIL, USER_PASSWORD, ADMIN_EMAIL, ADMIN_PASSWORD,
#   USER_POOL_ID, RATE_LIMIT_TARGET, EXPIRED_TOKEN
#

set -uo pipefail
export AWS_PAGER=""

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
BASE_URL="${BASE_URL:-https://rzgjdl59aj.execute-api.us-east-2.amazonaws.com/dev}"
USER_POOL_ID="${USER_POOL_ID:-us-east-2_ZEaM80bI4}"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-2}"
export AWS_DEFAULT_REGION

# Test users (user1 stays "user", user2 gets promoted to "admin" for the run)
USER_EMAIL="${USER_EMAIL:-kvora1008@gmail.com}"
USER_PASSWORD="${USER_PASSWORD:-TestPass123}"
ADMIN_EMAIL="${ADMIN_EMAIL:-desairaj1807@gmail.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-TestPass456}"

# How many requests scenario 8 should send (rate limit is 100/min)
RATE_LIMIT_TARGET="${RATE_LIMIT_TARGET:-150}"

# Optional: pre-captured expired token for scenario 5
EXPIRED_TOKEN="${EXPIRED_TOKEN:-}"
CACHE_DIR="$(dirname "$0")/.cache"
CACHE_FILE="${CACHE_DIR}/expired_token"

# ------------------------------------------------------------------------------
# Pretty output
# ------------------------------------------------------------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
DIM=$'\033[2m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

PASS=0
FAIL=0
SKIP=0
declare -a SUMMARY_ROWS=()

print_header() {
    echo
    echo "${BOLD}${BLUE}===============================================================${RESET}"
    echo "${BOLD}${BLUE}  $1${RESET}"
    echo "${BOLD}${BLUE}===============================================================${RESET}"
}

print_scenario() {
    echo
    echo "${BOLD}--- $1 ---${RESET}"
}

print_curl() {
    echo "${DIM}$ $1${RESET}"
}

record() {
    local name="$1" outcome="$2" detail="$3"
    case "$outcome" in
        PASS) PASS=$((PASS+1)); echo "${GREEN}[PASS]${RESET} $detail" ;;
        FAIL) FAIL=$((FAIL+1)); echo "${RED}[FAIL]${RESET} $detail" ;;
        SKIP) SKIP=$((SKIP+1)); echo "${YELLOW}[SKIP]${RESET} $detail" ;;
    esac
    SUMMARY_ROWS+=("$(printf '%-55s %s' "$name" "$outcome")")
}

abort() {
    echo "${RED}${BOLD}ABORT:${RESET} $1" >&2
    exit 1
}

# ------------------------------------------------------------------------------
# HTTP helpers
# ------------------------------------------------------------------------------

# Returns just the HTTP status code from a curl call.
# Body is captured to /tmp/zerowall_body for callers that need it.
http_status() {
    local method="$1" path="$2" token="${3:-}" data="${4:-}"
    local args=(-s -o /tmp/zerowall_body -w '%{http_code}' -X "$method" "$BASE_URL$path")
    if [[ -n "$token" ]]; then
        args+=(-H "Authorization: Bearer $token")
    fi
    if [[ -n "$data" ]]; then
        args+=(-H "Content-Type: application/json" -d "$data")
    fi
    curl "${args[@]}"
}

assert_status() {
    local expected="$1" actual="$2" name="$3"
    if [[ "$actual" == "$expected" ]]; then
        record "$name" PASS "expected $expected, got $actual"
    else
        record "$name" FAIL "expected $expected, got $actual (body: $(cat /tmp/zerowall_body 2>/dev/null | head -c 200))"
    fi
}

# ------------------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------------------

login() {
    local email="$1" password="$2"
    local body
    body=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"password\":\"$password\"}")
    echo "$body" | jq -r '.idToken // .data.idToken // empty'
}

set_role() {
    local email="$1" role="$2"
    aws cognito-idp admin-update-user-attributes \
        --user-pool-id "$USER_POOL_ID" \
        --username "$email" \
        --user-attributes "Name=custom:role,Value=$role" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# --prep-expired mode: capture a token now, save for use 65+ min later
# ------------------------------------------------------------------------------
if [[ "${1:-}" == "--prep-expired" ]]; then
    print_header "Pre-capture expired token"
    mkdir -p "$CACHE_DIR"
    echo "Logging in as $USER_EMAIL to capture a token..."
    token=$(login "$USER_EMAIL" "$USER_PASSWORD")
    if [[ -z "$token" ]]; then
        abort "Login failed. Check USER_EMAIL / USER_PASSWORD."
    fi
    echo "$token" > "$CACHE_FILE"
    date +%s > "${CACHE_FILE}.timestamp"
    echo "${GREEN}Token cached at $CACHE_FILE${RESET}"
    echo "It will be valid as 'expired' after $(date -d '+65 minutes' 2>/dev/null || date -v +65M 2>/dev/null || echo 'about 65 minutes from now')"
    exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
    exit 0
fi

# ------------------------------------------------------------------------------
# Setup phase
# ------------------------------------------------------------------------------
print_header "ZeroWall Attack Simulation"
echo "Base URL:    $BASE_URL"
echo "User pool:   $USER_POOL_ID"
echo "Region:      $AWS_DEFAULT_REGION"
echo

print_header "Setup"

echo "[setup] Promoting $ADMIN_EMAIL to admin..."
if ! set_role "$ADMIN_EMAIL" admin; then
    abort "Could not promote $ADMIN_EMAIL. Check AWS CLI creds and USER_POOL_ID."
fi

echo "[setup] Logging in as user ($USER_EMAIL)..."
USER_TOKEN=$(login "$USER_EMAIL" "$USER_PASSWORD")
[[ -n "$USER_TOKEN" ]] || abort "User login failed."

echo "[setup] Logging in as admin ($ADMIN_EMAIL)..."
ADMIN_TOKEN=$(login "$ADMIN_EMAIL" "$ADMIN_PASSWORD")
[[ -n "$ADMIN_TOKEN" ]] || abort "Admin login failed."

# Resolve expired token from env or cache
if [[ -z "$EXPIRED_TOKEN" && -f "$CACHE_FILE" && -f "${CACHE_FILE}.timestamp" ]]; then
    cached_at=$(cat "${CACHE_FILE}.timestamp")
    age=$(( $(date +%s) - cached_at ))
    if [[ $age -ge 3900 ]]; then
        EXPIRED_TOKEN=$(cat "$CACHE_FILE")
        echo "[setup] Using cached expired token (age: $((age/60)) min)"
    else
        echo "[setup] Cached token still fresh (age: $((age/60)) min, need >=65). Scenario 5 will SKIP."
    fi
fi

echo "${GREEN}[setup] Done.${RESET}"

# ------------------------------------------------------------------------------
# Scenarios
# ------------------------------------------------------------------------------
print_header "Scenarios"

# --- S01: Sign up ----------------------------------------------------------
print_scenario "S01 - Sign up"
print_curl "POST $BASE_URL/auth/signup"
status=$(http_status POST /auth/signup "" \
    "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}")
body=$(cat /tmp/zerowall_body)
if [[ "$status" == "200" || "$status" == "201" ]]; then
    record "S01 Sign up" PASS "status $status (new user created)"
elif echo "$body" | grep -qi "exists\|UsernameExists"; then
    record "S01 Sign up" PASS "status $status (user already exists, endpoint reachable)"
else
    record "S01 Sign up" FAIL "status $status, body: $body"
fi

# --- S02: Login ------------------------------------------------------------
print_scenario "S02 - Login (already done in setup, re-verifying)"
print_curl "POST $BASE_URL/auth/login"
status=$(http_status POST /auth/login "" \
    "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}")
assert_status 200 "$status" "S02 Login"

# --- S03: Create note with valid token -------------------------------------
print_scenario "S03 - Create note with valid token"
print_curl "POST $BASE_URL/notes (Authorization: Bearer <USER_TOKEN>)"
status=$(http_status POST /notes "$USER_TOKEN" \
    '{"title":"Phase5 attack test","content":"created by S03"}')
USER_NOTE_ID=$(jq -r '.data.noteId // .noteId // empty' /tmp/zerowall_body)
assert_status 201 "$status" "S03 Create note (user)"

# Also create a note as admin so S07 has something to delete
status=$(http_status POST /notes "$ADMIN_TOKEN" \
    '{"title":"Admin note","content":"created by admin for S07"}')
ADMIN_NOTE_ID=$(jq -r '.data.noteId // .noteId // empty' /tmp/zerowall_body)
if [[ -z "$ADMIN_NOTE_ID" ]]; then
    echo "${YELLOW}warn:${RESET} could not capture admin noteId; S07 may fail."
fi

# --- S04: Create note WITHOUT token ---------------------------------------
print_scenario "S04 - Create note WITHOUT token"
print_curl "POST $BASE_URL/notes (no Authorization header)"
status=$(http_status POST /notes "" '{"title":"x","content":"y"}')
assert_status 401 "$status" "S04 Create without token"

# --- S05: Create note with EXPIRED token ----------------------------------
print_scenario "S05 - Create note with expired token"
if [[ -z "$EXPIRED_TOKEN" ]]; then
    record "S05 Expired token" SKIP "no EXPIRED_TOKEN set and cache missing/fresh. Run with --prep-expired 65+ min before the demo, or set EXPIRED_TOKEN env var."
else
    print_curl "POST $BASE_URL/notes (Authorization: Bearer <EXPIRED_TOKEN>)"
    status=$(http_status POST /notes "$EXPIRED_TOKEN" '{"title":"x","content":"y"}')
    assert_status 401 "$status" "S05 Expired token"
fi

# --- S06: DELETE as user role (should be forbidden) -----------------------
print_scenario "S06 - DELETE as user role"
if [[ -z "$USER_NOTE_ID" ]]; then
    record "S06 DELETE as user" SKIP "no user noteId from S03"
else
    print_curl "DELETE $BASE_URL/notes/$USER_NOTE_ID (USER_TOKEN)"
    status=$(http_status DELETE "/notes/$USER_NOTE_ID" "$USER_TOKEN")
    assert_status 403 "$status" "S06 DELETE as user"
fi

# --- S07: DELETE as admin role --------------------------------------------
print_scenario "S07 - DELETE as admin role"
if [[ -z "$ADMIN_NOTE_ID" ]]; then
    record "S07 DELETE as admin" SKIP "no admin noteId from S03"
else
    print_curl "DELETE $BASE_URL/notes/$ADMIN_NOTE_ID (ADMIN_TOKEN)"
    status=$(http_status DELETE "/notes/$ADMIN_NOTE_ID" "$ADMIN_TOKEN")
    # Accept 200 or 204 (depends on handler)
    if [[ "$status" == "200" || "$status" == "204" ]]; then
        record "S07 DELETE as admin" PASS "expected 200/204, got $status"
    else
        record "S07 DELETE as admin" FAIL "expected 200/204, got $status (body: $(cat /tmp/zerowall_body | head -c 200))"
    fi
fi

# --- S08: Rate limiting (sequential, not parallel) -------------------------
print_scenario "S08 - Rate limiting ($RATE_LIMIT_TARGET sequential GETs)"
print_curl "GET $BASE_URL/notes  x$RATE_LIMIT_TARGET"
echo "${DIM}This takes ~$(( RATE_LIMIT_TARGET / 10 )) seconds. CloudShell-safe sequential loop.${RESET}"

count_200=0
count_429=0
count_other=0
first_429_at=0
for i in $(seq 1 "$RATE_LIMIT_TARGET"); do
    s=$(http_status GET /notes "$USER_TOKEN")
    case "$s" in
        200) count_200=$((count_200+1)) ;;
        429)
            count_429=$((count_429+1))
            [[ $first_429_at -eq 0 ]] && first_429_at=$i
            ;;
        *) count_other=$((count_other+1)) ;;
    esac
done

echo "  200: $count_200    429: $count_429    other: $count_other    first 429 at request: $first_429_at"
if [[ $count_429 -gt 0 && $first_429_at -ge 80 && $first_429_at -le 120 ]]; then
    record "S08 Rate limiting" PASS "$count_429 requests blocked, first 429 at #$first_429_at"
elif [[ $count_429 -gt 0 ]]; then
    record "S08 Rate limiting" PASS "blocked $count_429 requests (first 429 at #$first_429_at, expected ~100). Confirm RATE_LIMIT_PER_MINUTE."
else
    record "S08 Rate limiting" FAIL "no 429s seen. Confirm RATE_LIMIT_PER_MINUTE=100 on zerowall-notes-handler."
fi

# --- S09: Tampered token --------------------------------------------------
print_scenario "S09 - Tampered token"
# Flip the last character of the signature segment - guaranteed signature mismatch
TAMPERED_TOKEN="${USER_TOKEN%?}X"
print_curl "POST $BASE_URL/notes (Authorization: Bearer <TAMPERED_TOKEN>)"
status=$(http_status POST /notes "$TAMPERED_TOKEN" '{"title":"x","content":"y"}')
assert_status 401 "$status" "S09 Tampered token"

# --- S10: Replay (same token used twice) ----------------------------------
print_scenario "S10 - Replay (reusing valid token)"
print_curl "POST $BASE_URL/notes  x2 (same token)"
status1=$(http_status POST /notes "$USER_TOKEN" '{"title":"replay1","content":"a"}')
status2=$(http_status POST /notes "$USER_TOKEN" '{"title":"replay2","content":"b"}')
if [[ "$status1" == "201" && "$status2" == "201" ]]; then
    record "S10 Replay (token valid)" PASS "both calls 201. Token expiry is the protection."
else
    record "S10 Replay (token valid)" FAIL "got $status1 / $status2"
fi

# ------------------------------------------------------------------------------
# Teardown
# ------------------------------------------------------------------------------
print_header "Teardown"
echo "[teardown] Demoting $ADMIN_EMAIL back to 'user'..."
set_role "$ADMIN_EMAIL" user || echo "${YELLOW}warn:${RESET} demote failed; check Cognito console."

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
print_header "Summary"
for row in "${SUMMARY_ROWS[@]}"; do
    case "$row" in
        *PASS*) echo "${GREEN}$row${RESET}" ;;
        *FAIL*) echo "${RED}$row${RESET}" ;;
        *SKIP*) echo "${YELLOW}$row${RESET}" ;;
    esac
done
echo
echo "${BOLD}Total: ${GREEN}$PASS pass${RESET}${BOLD}, ${RED}$FAIL fail${RESET}${BOLD}, ${YELLOW}$SKIP skip${RESET}"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0