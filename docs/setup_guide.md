# ZeroWall Setup Guide

Step-by-step deployment for reproducing ZeroWall on a fresh AWS account in `us-east-2`. Total time: roughly 90 minutes if everything goes smoothly. Follow the phases in order — each one builds on the previous one.

---

## 0. Prerequisites

- An AWS account with admin or equivalent permissions
- AWS CLI v2 installed and configured (`aws configure`)
- Region set to `us-east-2`
- Python 3.12 installed locally for packaging Lambda code
- `jq` and `zip` available on PATH
- Cloned repo: `git clone https://github.com/Dhruvshelke15/zerowall.git`

Verify prerequisites:

```bash
aws sts get-caller-identity
aws configure get region    # should print us-east-2
python3 --version           # should print 3.12.x
jq --version
zip -h | head -1
```

If `aws configure get region` prints anything other than `us-east-2`, run `aws configure set region us-east-2`.

Throughout this guide, replace `<ACCOUNT_ID>` with your AWS account ID. You can get it from `aws sts get-caller-identity --query Account --output text`.

---

## Phase 1: Foundation (DynamoDB, Cognito, RBAC, Auth Handler)

### 1.1 Create the four DynamoDB tables

```bash
cd zerowall
python3 scripts/create_tables.py
```

This creates `zerowall-notes`, `zerowall-roles`, `zerowall-rate-limits`, and `zerowall-audit-log` with PAY_PER_REQUEST billing and TTL enabled where applicable. Verify:

```bash
aws dynamodb list-tables --region us-east-2 --query "TableNames[?starts_with(@,'zerowall-')]"
```

### 1.2 Seed the RBAC roles table

```bash
python3 scripts/seed_roles.py
```

Adds the `user` and `admin` role definitions to `zerowall-roles`. Verify:

```bash
aws dynamodb scan --table-name zerowall-roles --region us-east-2 --query "Items[].role.S"
```

### 1.3 Create the Cognito user pool and app client

```bash
python3 scripts/setup_cognito.py
```

The script prints the User Pool ID and Client ID at the end. **Save these** — you'll need them for Lambda env vars in every subsequent step.

Set them as shell variables for the rest of this session:

```bash
export USER_POOL_ID=<paste-pool-id>
export CLIENT_ID=<paste-client-id>
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### 1.4 Create the IAM role for the auth handler

```bash
aws iam create-role --role-name zerowall-auth-handler-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy --role-name zerowall-auth-handler-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy --role-name zerowall-auth-handler-role --policy-name cognito-access --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cognito-idp:SignUp","cognito-idp:AdminConfirmSignUp","cognito-idp:InitiateAuth","cognito-idp:AdminUpdateUserAttributes"],"Resource":"arn:aws:cognito-idp:us-east-2:'"$ACCOUNT_ID"':userpool/'"$USER_POOL_ID"'"}]}'
```

Wait ~10 seconds for IAM propagation before the next step.

### 1.5 Deploy the auth handler Lambda

```bash
cd lambdas/auth_handler
zip -r ../../auth_handler.zip handler.py
cd ../..

aws lambda create-function --function-name zerowall-auth-handler --runtime python3.12 --role arn:aws:iam::$ACCOUNT_ID:role/zerowall-auth-handler-role --handler handler.lambda_handler --zip-file fileb://auth_handler.zip --timeout 10 --environment "Variables={APP_REGION=us-east-2,COGNITO_USER_POOL_ID=$USER_POOL_ID,COGNITO_CLIENT_ID=$CLIENT_ID}" --region us-east-2

rm auth_handler.zip
```

### 1.6 Create the API Gateway and the auth routes

```bash
API_ID=$(aws apigateway create-rest-api --name zerowall-api --region us-east-2 --query id --output text)
echo "API_ID=$API_ID"
export API_ID

ROOT_ID=$(aws apigateway get-resources --rest-api-id $API_ID --region us-east-2 --query "items[?path=='/'].id" --output text)
```

Create `/auth/signup`, `/auth/login`, `/auth/refresh` routes. Each needs three commands (create resource, create method, integrate to Lambda). For brevity use the script `scripts/setup_api_routes.sh` if it exists, or set up via the AWS Console under API Gateway → zerowall-api → Resources → Create Resource → Create Method → Lambda Proxy Integration → zerowall-auth-handler.

After all three routes are wired, deploy the API:

```bash
aws apigateway create-deployment --rest-api-id $API_ID --stage-name dev --region us-east-2

export BASE_URL="https://$API_ID.execute-api.us-east-2.amazonaws.com/dev"
echo "BASE_URL=$BASE_URL"
```

Test:

```bash
curl -X POST $BASE_URL/auth/signup -H "Content-Type: application/json" -d '{"email":"test@example.com","password":"TestPass123"}'
```

A 200 (or a structured error if the user already exists) confirms Phase 1 is complete.

---

## Phase 2: Lambda Authorizer + RBAC

### 2.1 Build the dependency layer

```bash
mkdir -p layer/python
pip install -t layer/python PyJWT==2.9.0 cryptography==43.0.0
cd layer && zip -r ../zerowall-deps.zip python && cd ..

LAYER_ARN=$(aws lambda publish-layer-version --layer-name zerowall-deps --zip-file fileb://zerowall-deps.zip --compatible-runtimes python3.12 --region us-east-2 --query LayerVersionArn --output text)
echo "LAYER_ARN=$LAYER_ARN"

rm -rf layer zerowall-deps.zip
```

### 2.2 Create the IAM role for the authorizer

```bash
aws iam create-role --role-name zerowall-authorizer-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy --role-name zerowall-authorizer-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy --role-name zerowall-authorizer-role --policy-name dynamodb-roles-read --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:us-east-2:'"$ACCOUNT_ID"':table/zerowall-roles"}]}'
```

### 2.3 Deploy the authorizer Lambda

```bash
cd lambdas/authorizer
zip -r ../../authorizer.zip handler.py jwt_utils.py
cd ../..

aws lambda create-function --function-name zerowall-authorizer --runtime python3.12 --role arn:aws:iam::$ACCOUNT_ID:role/zerowall-authorizer-role --handler handler.lambda_handler --zip-file fileb://authorizer.zip --timeout 10 --layers $LAYER_ARN --environment "Variables={APP_REGION=us-east-2,COGNITO_USER_POOL_ID=$USER_POOL_ID,COGNITO_CLIENT_ID=$CLIENT_ID}" --region us-east-2

rm authorizer.zip
```

### 2.4 Attach the authorizer to the API Gateway

```bash
AUTHORIZER_ARN="arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:$ACCOUNT_ID:function:zerowall-authorizer/invocations"

AUTHORIZER_ID=$(aws apigateway create-authorizer --rest-api-id $API_ID --name zerowall-jwt-authorizer --type REQUEST --authorizer-uri $AUTHORIZER_ARN --identity-source method.request.header.Authorization --authorizer-result-ttl-in-seconds 0 --region us-east-2 --query id --output text)
echo "AUTHORIZER_ID=$AUTHORIZER_ID"

aws lambda add-permission --function-name zerowall-authorizer --statement-id apigateway-invoke --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:us-east-2:$ACCOUNT_ID:$API_ID/authorizers/$AUTHORIZER_ID" --region us-east-2
```

---

## Phase 3: Notes Handler + Rate Limiting

### 3.1 Create the IAM role for the notes handler

```bash
aws iam create-role --role-name zerowall-notes-handler-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy --role-name zerowall-notes-handler-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy --role-name zerowall-notes-handler-role --policy-name dynamodb-notes-access --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:PutItem","dynamodb:UpdateItem","dynamodb:DeleteItem","dynamodb:Query"],"Resource":["arn:aws:dynamodb:us-east-2:'"$ACCOUNT_ID"':table/zerowall-notes","arn:aws:dynamodb:us-east-2:'"$ACCOUNT_ID"':table/zerowall-rate-limits","arn:aws:dynamodb:us-east-2:'"$ACCOUNT_ID"':table/zerowall-audit-log"]}]}'
```

### 3.2 Deploy the notes handler

```bash
cd lambdas/notes_handler
zip -r ../../notes_handler.zip *.py
cd ../..

aws lambda create-function --function-name zerowall-notes-handler --runtime python3.12 --role arn:aws:iam::$ACCOUNT_ID:role/zerowall-notes-handler-role --handler handler.lambda_handler --zip-file fileb://notes_handler.zip --timeout 10 --environment "Variables={APP_REGION=us-east-2,RATE_LIMIT_PER_MINUTE=100}" --region us-east-2

rm notes_handler.zip
```

### 3.3 Wire up the protected routes

For each route below, use the AWS Console (API Gateway → Resources → Create Resource → Create Method) with the authorizer `zerowall-jwt-authorizer` attached and Lambda Proxy Integration to `zerowall-notes-handler`:

- `GET /notes`
- `POST /notes`
- `GET /notes/{noteId}`
- `PUT /notes/{noteId}`
- `DELETE /notes/{noteId}`

After all routes are wired, redeploy:

```bash
aws apigateway create-deployment --rest-api-id $API_ID --stage-name dev --region us-east-2
```

---

## Phase 4: Monitoring (SNS, Metric Filters, Alarms, Anomaly Checker, Dashboard)

### 4.1 Create the SNS topic and subscribe team emails

```bash
SNS_TOPIC_ARN=$(aws sns create-topic --name zerowall-alerts --region us-east-2 --query TopicArn --output text)
echo "SNS_TOPIC_ARN=$SNS_TOPIC_ARN"

aws sns subscribe --topic-arn $SNS_TOPIC_ARN --protocol email --notification-endpoint your.email@example.com --region us-east-2
```

Each subscriber receives a confirmation email and must click the link to activate.

> **Gmail caveat:** Gmail's filters auto-unsubscribe SNS confirmation links if you click them directly. Right-click the link, copy URL, paste in a fresh browser tab to confirm reliably.

### 4.2 Create CloudWatch metric filters

```bash
aws logs put-metric-filter --log-group-name /aws/lambda/zerowall-authorizer --filter-name zerowall-auth-failures --filter-pattern '{ ($.logType = "authz") && ($.result != "ALLOWED") }' --metric-transformations metricName=AuthFailures,metricNamespace=zerowall,metricValue=1 --region us-east-2

aws logs put-metric-filter --log-group-name /aws/lambda/zerowall-notes-handler --filter-name zerowall-rate-limit-hits --filter-pattern '{ ($.logType = "audit") && ($.result = "DENIED_RATE_LIMIT") }' --metric-transformations metricName=RateLimitHits,metricNamespace=zerowall,metricValue=1 --region us-east-2

aws logs put-metric-filter --log-group-name /aws/lambda/zerowall-notes-handler --filter-name zerowall-request-latency --filter-pattern '{ $.logType = "audit" }' --metric-transformations metricName=RequestLatency,metricNamespace=zerowall,metricValue='$.latencyMs' --region us-east-2
```

### 4.3 Create CloudWatch alarms

```bash
aws cloudwatch put-metric-alarm --alarm-name zerowall-high-auth-failures --metric-name AuthFailures --namespace zerowall --statistic Sum --period 300 --threshold 20 --comparison-operator GreaterThanThreshold --evaluation-periods 1 --alarm-actions $SNS_TOPIC_ARN --treat-missing-data notBreaching --region us-east-2

aws cloudwatch put-metric-alarm --alarm-name zerowall-rate-limit-spike --metric-name RateLimitHits --namespace zerowall --statistic Sum --period 300 --threshold 50 --comparison-operator GreaterThanThreshold --evaluation-periods 1 --alarm-actions $SNS_TOPIC_ARN --treat-missing-data notBreaching --region us-east-2

aws cloudwatch put-metric-alarm --alarm-name zerowall-high-latency --metric-name RequestLatency --namespace zerowall --statistic Average --period 300 --threshold 3000 --comparison-operator GreaterThanThreshold --evaluation-periods 1 --alarm-actions $SNS_TOPIC_ARN --treat-missing-data notBreaching --region us-east-2
```

### 4.4 Deploy the anomaly checker Lambda

```bash
aws iam create-role --role-name zerowall-anomaly-checker-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy --role-name zerowall-anomaly-checker-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy --role-name zerowall-anomaly-checker-role --policy-name audit-and-sns --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:Scan","Resource":"arn:aws:dynamodb:us-east-2:'"$ACCOUNT_ID"':table/zerowall-audit-log"},{"Effect":"Allow","Action":"sns:Publish","Resource":"'"$SNS_TOPIC_ARN"'"}]}'

cd lambdas/anomaly_checker
zip -r ../../anomaly_checker.zip handler.py
cd ../..

aws lambda create-function --function-name zerowall-anomaly-checker --runtime python3.12 --role arn:aws:iam::$ACCOUNT_ID:role/zerowall-anomaly-checker-role --handler handler.lambda_handler --zip-file fileb://anomaly_checker.zip --timeout 30 --environment "Variables={APP_REGION=us-east-2,AUDIT_LOG_TABLE=zerowall-audit-log,SNS_TOPIC_ARN=$SNS_TOPIC_ARN,LOOKBACK_MINUTES=5,BRUTE_FORCE_DENIED_THRESHOLD=5,MULTI_IP_THRESHOLD=2,RATE_LIMIT_SPIKE_THRESHOLD=20}" --region us-east-2

rm anomaly_checker.zip
```

### 4.5 Schedule the anomaly checker via EventBridge

```bash
aws events put-rule --name zerowall-anomaly-checker-schedule --schedule-expression "rate(5 minutes)" --state ENABLED --region us-east-2

aws lambda add-permission --function-name zerowall-anomaly-checker --statement-id eventbridge-invoke --action lambda:InvokeFunction --principal events.amazonaws.com --source-arn "arn:aws:events:us-east-2:$ACCOUNT_ID:rule/zerowall-anomaly-checker-schedule" --region us-east-2

aws events put-targets --rule zerowall-anomaly-checker-schedule --targets "Id=1,Arn=arn:aws:lambda:us-east-2:$ACCOUNT_ID:function:zerowall-anomaly-checker" --region us-east-2
```

### 4.6 Create the CloudWatch dashboard

```bash
aws cloudwatch put-dashboard --dashboard-name zerowall-dashboard --dashboard-body file://zerowall-dashboard.json --region us-east-2
```

The dashboard JSON is at the repo root.

---

## Phase 5: Verify the deployment

Run the attack script:

```bash
chmod +x scripts/test_attacks.sh
./scripts/test_attacks.sh
```

Expected output: 9 PASS, 0 FAIL, 1 SKIP (S05 - expired token, requires `--prep-expired` 65+ min in advance).

If S08 (Tampered token) returns anything other than 401, the deployed authorizer code is out of sync with the repo. Redeploy:

```bash
cd lambdas/authorizer && zip -r ../../authorizer.zip handler.py jwt_utils.py && cd ../..
aws lambda update-function-code --function-name zerowall-authorizer --zip-file fileb://authorizer.zip --region us-east-2
rm authorizer.zip
```

This issue was caught during Phase 5 attack testing on the original deployment — see the demo script for context.

---

## Teardown

When you're done with the deployment (after the demo, or to stop accruing charges):

```bash
./scripts/teardown.sh --dry-run    # see what would be deleted
./scripts/teardown.sh              # actually delete (requires typing 'DELETE ZEROWALL' to confirm)
```

The teardown script handles all 12 resource categories in the correct order. See `scripts/teardown.sh --help` for details.

---

## Appendix: account-specific values reference

After completing the setup, capture these values for the team. They'll be needed any time you re-run scripts or hand the project off:

| Variable | Where to find it | Example |
|---|---|---|
| Account ID | `aws sts get-caller-identity --query Account` | `308621094240` |
| User Pool ID | output of `setup_cognito.py` | `us-east-2_ZEaM80bI4` |
| Client ID | output of `setup_cognito.py` | `23of1dsb89ivsrl2bptq7l03k1` |
| API ID | `$API_ID` after Phase 1.6 | `rzgjdl59aj` |
| Base URL | `$BASE_URL` after Phase 1.6 | `https://rzgjdl59aj.execute-api.us-east-2.amazonaws.com/dev` |
| SNS topic ARN | `$SNS_TOPIC_ARN` after Phase 4.1 | `arn:aws:sns:us-east-2:308621094240:zerowall-alerts` |
| Layer ARN | `$LAYER_ARN` after Phase 2.1 | `arn:aws:lambda:us-east-2:...:layer:zerowall-deps:1` |