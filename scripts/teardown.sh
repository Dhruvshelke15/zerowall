#!/usr/bin/env bash
#
# ZeroWall - Teardown Script (Phase 5)
#
# Deletes EVERY AWS resource the project created, in the correct order
# (children before parents). Idempotent: if a resource is already gone,
# the step is skipped, not failed.
#
# Modes:
#   ./teardown.sh               Prompts to type 'DELETE ZEROWALL' to confirm
#   ./teardown.sh --dry-run     Shows what would be deleted, runs no commands
#   ./teardown.sh --force       Skips the confirmation prompt
#   ./teardown.sh --help        Print this help
#
# DO NOT RUN BEFORE THE DEMO. This is a one-way operation.
#

set -uo pipefail
export AWS_PAGER=""

# ------------------------------------------------------------------------------
# Config (must match resource names from Phase 1-4)
# ------------------------------------------------------------------------------
REGION="us-east-2"
EXPECTED_ACCOUNT_ID="308621094240"

LAMBDA_FUNCTIONS=(
    "zerowall-auth-handler"
    "zerowall-authorizer"
    "zerowall-notes-handler"
    "zerowall-anomaly-checker"
)

LAMBDA_LAYER="zerowall-deps"
API_NAME="zerowall-api"
COGNITO_POOL_ID="us-east-2_ZEaM80bI4"
SNS_TOPIC_ARN="arn:aws:sns:us-east-2:308621094240:zerowall-alerts"
DASHBOARD="zerowall-dashboard"
EVENTBRIDGE_RULE="zerowall-anomaly-checker-schedule"

DYNAMODB_TABLES=(
    "zerowall-notes"
    "zerowall-roles"
    "zerowall-rate-limits"
    "zerowall-audit-log"
)

ALARMS=(
    "zerowall-high-auth-failures"
    "zerowall-rate-limit-spike"
    "zerowall-high-latency"
)

# Metric filters: name|log-group  (filters live ON log groups, so format pairs them)
METRIC_FILTERS=(
    "zerowall-auth-failures|/aws/lambda/zerowall-authorizer"
    "zerowall-rate-limit-hits|/aws/lambda/zerowall-notes-handler"
    "zerowall-request-latency|/aws/lambda/zerowall-notes-handler"
)

LOG_GROUPS=(
    "/aws/lambda/zerowall-auth-handler"
    "/aws/lambda/zerowall-authorizer"
    "/aws/lambda/zerowall-notes-handler"
    "/aws/lambda/zerowall-anomaly-checker"
    "/zerowall/audit-log"
)

IAM_ROLES=(
    "zerowall-auth-handler-role"
    "zerowall-authorizer-role"
    "zerowall-notes-handler-role"
    "zerowall-anomaly-checker-role"
)

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

DRY_RUN="false"
FORCE="false"
SUCCESS=0
SKIPPED=0
FAILED=0
STEP=0
TOTAL_STEPS=12

print_step() {
    STEP=$((STEP+1))
    echo
    echo "${BOLD}${BLUE}[$STEP/$TOTAL_STEPS] $1${RESET}"
}

ok()   { echo "  ${GREEN}✓${RESET} $1"; SUCCESS=$((SUCCESS+1)); }
skip() { echo "  ${YELLOW}!${RESET} $1"; SKIPPED=$((SKIPPED+1)); }
fail() { echo "  ${RED}✗${RESET} $1"; FAILED=$((FAILED+1)); }

# Wraps an aws command. In dry-run mode, just prints what would run.
run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  ${DIM}[dry-run]${RESET} $*"
        return 0
    fi
    "$@"
}

# ------------------------------------------------------------------------------
# Args + help
# ------------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN="true" ;;
        --force)   FORCE="true" ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "${RED}Unknown arg:${RESET} $arg" >&2
            echo "Run with --help for usage." >&2
            exit 2
            ;;
    esac
done

# ------------------------------------------------------------------------------
# Pre-flight: AWS CLI configured? Right account?
# ------------------------------------------------------------------------------
echo "${BOLD}${BLUE}===============================================================${RESET}"
echo "${BOLD}${BLUE}  ZeroWall Teardown${RESET}"
echo "${BOLD}${BLUE}===============================================================${RESET}"

if ! caller=$(aws sts get-caller-identity --output json 2>/dev/null); then
    echo "${RED}${BOLD}ABORT:${RESET} AWS CLI is not configured. Run 'aws configure' first." >&2
    exit 1
fi
account_id=$(echo "$caller" | grep -o '"Account": "[^"]*"' | cut -d'"' -f4)
arn=$(echo "$caller" | grep -o '"Arn": "[^"]*"' | cut -d'"' -f4)

echo "Region:    $REGION"
echo "Account:   $account_id"
echo "Identity:  $arn"
echo "Mode:      $([ "$DRY_RUN" == "true" ] && echo 'DRY RUN' || echo 'LIVE DELETE')"

if [[ "$account_id" != "$EXPECTED_ACCOUNT_ID" ]]; then
    echo
    echo "${RED}${BOLD}ABORT:${RESET} You are logged into account $account_id, but ZeroWall lives in $EXPECTED_ACCOUNT_ID." >&2
    echo "Refusing to run to avoid accidentally deleting resources in the wrong account." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Confirmation
# ------------------------------------------------------------------------------
if [[ "$DRY_RUN" != "true" && "$FORCE" != "true" ]]; then
    echo
    echo "${RED}${BOLD}This permanently deletes every ZeroWall AWS resource.${RESET}"
    echo
    echo "Will delete:"
    echo "  - ${#LAMBDA_FUNCTIONS[@]} Lambda functions + 1 layer (all versions)"
    echo "  - 1 API Gateway ($API_NAME)"
    echo "  - 1 EventBridge rule"
    echo "  - ${#ALARMS[@]} CloudWatch alarms, ${#METRIC_FILTERS[@]} metric filters, 1 dashboard"
    echo "  - ${#LOG_GROUPS[@]} CloudWatch log groups (this includes log history)"
    echo "  - 1 SNS topic + all subscriptions"
    echo "  - ${#DYNAMODB_TABLES[@]} DynamoDB tables (this includes all data)"
    echo "  - 1 Cognito user pool (this includes all users)"
    echo "  - ${#IAM_ROLES[@]} IAM roles + their policies"
    echo
    echo "${YELLOW}There is no undo. Capture anything you need to keep first.${RESET}"
    echo
    read -r -p "Type 'DELETE ZEROWALL' to confirm: " confirm
    if [[ "$confirm" != "DELETE ZEROWALL" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# ------------------------------------------------------------------------------
# Step 1 - EventBridge rule (disable, remove targets, delete)
# ------------------------------------------------------------------------------
print_step "EventBridge rule: $EVENTBRIDGE_RULE"
if aws events describe-rule --name "$EVENTBRIDGE_RULE" --region "$REGION" >/dev/null 2>&1; then
    run aws events disable-rule --name "$EVENTBRIDGE_RULE" --region "$REGION" >/dev/null 2>&1
    target_ids=$(aws events list-targets-by-rule --rule "$EVENTBRIDGE_RULE" --region "$REGION" --query 'Targets[].Id' --output text 2>/dev/null)
    if [[ -n "$target_ids" && "$target_ids" != "None" ]]; then
        # shellcheck disable=SC2086
        run aws events remove-targets --rule "$EVENTBRIDGE_RULE" --ids $target_ids --region "$REGION" >/dev/null 2>&1
    fi
    if run aws events delete-rule --name "$EVENTBRIDGE_RULE" --region "$REGION" 2>/dev/null; then
        ok "deleted"
    else
        fail "delete failed"
    fi
else
    skip "rule not found"
fi

# ------------------------------------------------------------------------------
# Step 2 - Lambda functions
# ------------------------------------------------------------------------------
print_step "Lambda functions"
for fn in "${LAMBDA_FUNCTIONS[@]}"; do
    if aws lambda get-function --function-name "$fn" --region "$REGION" >/dev/null 2>&1; then
        if run aws lambda delete-function --function-name "$fn" --region "$REGION" 2>/dev/null; then
            ok "$fn"
        else
            fail "$fn delete failed"
        fi
    else
        skip "$fn not found"
    fi
done

# ------------------------------------------------------------------------------
# Step 3 - Lambda layer (all versions)
# ------------------------------------------------------------------------------
print_step "Lambda layer: $LAMBDA_LAYER"
versions=$(aws lambda list-layer-versions --layer-name "$LAMBDA_LAYER" --region "$REGION" --query 'LayerVersions[].Version' --output text 2>/dev/null)
if [[ -z "$versions" || "$versions" == "None" ]]; then
    skip "layer not found"
else
    for v in $versions; do
        if run aws lambda delete-layer-version --layer-name "$LAMBDA_LAYER" --version-number "$v" --region "$REGION" 2>/dev/null; then
            ok "version $v"
        else
            fail "version $v delete failed"
        fi
    done
fi

# ------------------------------------------------------------------------------
# Step 4 - API Gateway
# ------------------------------------------------------------------------------
print_step "API Gateway: $API_NAME"
api_id=$(aws apigateway get-rest-apis --region "$REGION" --query "items[?name=='$API_NAME'].id" --output text 2>/dev/null)
if [[ -z "$api_id" || "$api_id" == "None" ]]; then
    skip "API not found"
else
    if run aws apigateway delete-rest-api --rest-api-id "$api_id" --region "$REGION" 2>/dev/null; then
        ok "deleted (id: $api_id)"
    else
        fail "delete failed"
    fi
fi

# ------------------------------------------------------------------------------
# Step 5 - CloudWatch alarms
# ------------------------------------------------------------------------------
print_step "CloudWatch alarms"
existing=$(aws cloudwatch describe-alarms --alarm-names "${ALARMS[@]}" --region "$REGION" --query 'MetricAlarms[].AlarmName' --output text 2>/dev/null)
if [[ -z "$existing" || "$existing" == "None" ]]; then
    skip "no alarms found"
else
    if run aws cloudwatch delete-alarms --alarm-names "${ALARMS[@]}" --region "$REGION" 2>/dev/null; then
        for a in "${ALARMS[@]}"; do
            if echo "$existing" | grep -qw "$a"; then
                ok "$a"
            else
                skip "$a (not found)"
            fi
        done
    else
        fail "alarm batch delete failed"
    fi
fi

# ------------------------------------------------------------------------------
# Step 6 - CloudWatch metric filters
# ------------------------------------------------------------------------------
print_step "CloudWatch metric filters"
for entry in "${METRIC_FILTERS[@]}"; do
    name="${entry%%|*}"
    log_group="${entry##*|}"
    if aws logs describe-metric-filters --log-group-name "$log_group" --filter-name-prefix "$name" --region "$REGION" --query 'metricFilters[?filterName==`'"$name"'`]' --output text 2>/dev/null | grep -q .; then
        if run aws logs delete-metric-filter --log-group-name "$log_group" --filter-name "$name" --region "$REGION" 2>/dev/null; then
            ok "$name"
        else
            fail "$name delete failed"
        fi
    else
        skip "$name (not found on $log_group)"
    fi
done

# ------------------------------------------------------------------------------
# Step 7 - CloudWatch dashboard
# ------------------------------------------------------------------------------
print_step "CloudWatch dashboard: $DASHBOARD"
if aws cloudwatch get-dashboard --dashboard-name "$DASHBOARD" --region "$REGION" >/dev/null 2>&1; then
    if run aws cloudwatch delete-dashboards --dashboard-names "$DASHBOARD" --region "$REGION" 2>/dev/null; then
        ok "deleted"
    else
        fail "delete failed"
    fi
else
    skip "dashboard not found"
fi

# ------------------------------------------------------------------------------
# Step 8 - CloudWatch log groups (after metric filters are gone)
# ------------------------------------------------------------------------------
print_step "CloudWatch log groups"
for lg in "${LOG_GROUPS[@]}"; do
    found=$(aws logs describe-log-groups --log-group-name-prefix "$lg" --region "$REGION" --query 'logGroups[?logGroupName==`'"$lg"'`].logGroupName' --output text 2>/dev/null)
    if [[ -n "$found" && "$found" != "None" ]]; then
        if run aws logs delete-log-group --log-group-name "$lg" --region "$REGION" 2>/dev/null; then
            ok "$lg"
        else
            fail "$lg delete failed"
        fi
    else
        skip "$lg not found"
    fi
done

# ------------------------------------------------------------------------------
# Step 9 - SNS topic (subscriptions deleted automatically with the topic)
# ------------------------------------------------------------------------------
print_step "SNS topic"
if aws sns get-topic-attributes --topic-arn "$SNS_TOPIC_ARN" --region "$REGION" >/dev/null 2>&1; then
    if run aws sns delete-topic --topic-arn "$SNS_TOPIC_ARN" --region "$REGION" 2>/dev/null; then
        ok "deleted (subscriptions removed automatically)"
    else
        fail "delete failed"
    fi
else
    skip "topic not found"
fi

# ------------------------------------------------------------------------------
# Step 10 - DynamoDB tables
# ------------------------------------------------------------------------------
print_step "DynamoDB tables"
for t in "${DYNAMODB_TABLES[@]}"; do
    if aws dynamodb describe-table --table-name "$t" --region "$REGION" >/dev/null 2>&1; then
        if run aws dynamodb delete-table --table-name "$t" --region "$REGION" >/dev/null 2>&1; then
            ok "$t"
        else
            fail "$t delete failed"
        fi
    else
        skip "$t not found"
    fi
done

# ------------------------------------------------------------------------------
# Step 11 - Cognito user pool
# ------------------------------------------------------------------------------
print_step "Cognito user pool: $COGNITO_POOL_ID"
if aws cognito-idp describe-user-pool --user-pool-id "$COGNITO_POOL_ID" --region "$REGION" >/dev/null 2>&1; then
    # Disable deletion protection if it's on (Cognito default since 2023 is INACTIVE, but be safe)
    run aws cognito-idp update-user-pool --user-pool-id "$COGNITO_POOL_ID" --deletion-protection INACTIVE --region "$REGION" >/dev/null 2>&1 || true
    if run aws cognito-idp delete-user-pool --user-pool-id "$COGNITO_POOL_ID" --region "$REGION" 2>/dev/null; then
        ok "deleted"
    else
        fail "delete failed (check console for deletion protection status)"
    fi
else
    skip "pool not found"
fi

# ------------------------------------------------------------------------------
# Step 12 - IAM roles (last - Lambdas and others must be gone first)
# ------------------------------------------------------------------------------
print_step "IAM roles"
for role in "${IAM_ROLES[@]}"; do
    if ! aws iam get-role --role-name "$role" >/dev/null 2>&1; then
        skip "$role not found"
        continue
    fi
    # Detach managed policies
    attached=$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    if [[ -n "$attached" && "$attached" != "None" ]]; then
        for arn in $attached; do
            run aws iam detach-role-policy --role-name "$role" --policy-arn "$arn" >/dev/null 2>&1 || true
        done
    fi
    # Delete inline policies
    inline=$(aws iam list-role-policies --role-name "$role" --query 'PolicyNames[]' --output text 2>/dev/null)
    if [[ -n "$inline" && "$inline" != "None" ]]; then
        for name in $inline; do
            run aws iam delete-role-policy --role-name "$role" --policy-name "$name" >/dev/null 2>&1 || true
        done
    fi
    # Delete role
    if run aws iam delete-role --role-name "$role" 2>/dev/null; then
        ok "$role"
    else
        fail "$role delete failed (may still have attached policies)"
    fi
done

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo
echo "${BOLD}${BLUE}===============================================================${RESET}"
echo "${BOLD}${BLUE}  Summary${RESET}"
echo "${BOLD}${BLUE}===============================================================${RESET}"
echo "  ${GREEN}✓ Deleted:    $SUCCESS${RESET}"
echo "  ${YELLOW}! Skipped:    $SKIPPED${RESET}  (resource already gone)"
echo "  ${RED}✗ Failed:     $FAILED${RESET}"
echo

if [[ "$DRY_RUN" == "true" ]]; then
    echo "${YELLOW}This was a dry run. No resources were actually deleted.${RESET}"
    echo "Run without --dry-run to perform the actual teardown."
fi

if [[ $FAILED -gt 0 ]]; then
    echo "${RED}Some deletions failed. Re-run the script to retry, or check the AWS console.${RESET}"
    exit 1
fi
exit 0