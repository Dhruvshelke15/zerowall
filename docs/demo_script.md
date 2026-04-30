# ZeroWall Demo Script

A 10-minute live demo of the ZeroWall zero-trust API gateway. Two parts: architecture walkthrough (~3 min) and live demo (~7 min). Contingency plans at the end for things that might go sideways.

---

## Pre-demo checklist

### 65+ minutes before

- [ ] Run `./scripts/test_attacks.sh --prep-expired` to capture a token that will be expired by demo time. This unlocks scenario S05 (Expired token). Without this, S05 will SKIP.

### 5 minutes before

- [ ] Verify rate limit is set to 100/min:
  ```bash
  aws lambda get-function-configuration --function-name zerowall-notes-handler --region us-east-2 --query "Environment.Variables.RATE_LIMIT_PER_MINUTE" --output text
  ```
- [ ] Verify both test users exist and one is `user`, one will be promoted to `admin` by the script.
- [ ] Open these tabs/windows side by side:
  - Postman with the ZeroWall collection loaded and the Dev environment selected
  - CloudWatch dashboard: `https://us-east-2.console.aws.amazon.com/cloudwatch/home?region=us-east-2#dashboards/dashboard/zerowall-dashboard`
  - DynamoDB console showing the `zerowall-audit-log` table
  - Email inbox (for the SNS alert that should arrive during the demo)
  - A terminal in the repo root (in case live debugging is needed)

### 1 minute before

- [ ] Make sure the EventBridge anomaly checker rule is ENABLED (it needs to be live so we can show the alert flow):
  ```bash
  aws events describe-rule --name zerowall-anomaly-checker-schedule --region us-east-2 --query "State"
  ```
  Should print `"ENABLED"`. If `"DISABLED"`, enable it now.
- [ ] Take a deep breath. The system is solid. We caught and fixed the only real bug during Phase 5 testing.

---

## Part 1: Architecture walkthrough (~3 min)

> **Open the architecture diagram from the spec on screen. Section 3.1.**

**Opening line:** "ZeroWall is a serverless zero-trust API gateway on AWS. The principle behind zero-trust is simple: never trust, always verify. Every request gets authenticated, authorized, rate-limited, and logged before it touches any business logic. We built it to protect a Notes API as the demo target, but the gateway is the actual product."

**The flow, layer by layer:**

> **Trace the diagram top to bottom while talking.**

"A request comes in to API Gateway. Before the request can reach any handler, it hits the Lambda Authorizer. The authorizer pulls the JWT from the Authorization header, verifies the signature against Cognito's public keys, checks expiration, extracts the user's role from the token claims, and looks up that role's permissions in DynamoDB. If anything fails — bad signature, expired token, wrong role for the requested resource — the authorizer returns DENY and API Gateway responds with 401 or 403. The notes handler never runs."

"If the authorizer approves, the request reaches the notes handler. First thing the handler does is check the rate limit — a per-user, per-minute counter in DynamoDB with TTL on each entry. Default threshold is 100 requests per minute per user. Over that, the handler returns 429 immediately."

"If the rate limit allows the request through, the CRUD operation runs. Critical detail here: the user ID for the DynamoDB partition key always comes from the authorizer context, never from the request body. Users physically cannot query another user's partition. That's data isolation enforced at the storage layer."

"Every step logs structured JSON to CloudWatch — the authorizer logs every authz decision, the notes handler logs every audit entry. CloudWatch metric filters extract three metrics: auth failures, rate limit hits, and request latency. Three alarms watch those metrics and fire SNS notifications to the team's email when thresholds are breached. Separately, an anomaly checker Lambda runs every 5 minutes via EventBridge, scanning the audit log for patterns like brute force attempts and publishing findings to the same SNS topic."

**Map to the four zero-trust principles:**

> **Optional. Skip if running long.**

- "Never trust, always verify" — the authorizer runs on every request, with caching off
- "Least privilege" — each Lambda has its own IAM role with only the permissions it needs
- "Assume breach" — the rate limiter and audit log run independently, even on authenticated requests
- "Log everything" — three metric filters, full audit trail, anomaly detection

---

## Part 2: Live demo (~7 min)

> **Switch to Postman. Have the dashboard tab and audit log tab one click away.**

The demo runs the 10 scenarios in order. Each one targets a specific security guarantee. Run them via Postman so the audience can read the requests, headers, and responses on screen.

### S01 — Sign up

**Click:** Auth → S01 - Sign up → Send

**Say:** "Standard signup endpoint. Returns 200 if new, or a structured error if the user already exists. Either way, this is a public endpoint — no auth needed to register."

**Expected:** 200 or 409. Either is fine.

### S02 — Login

**Click:** Auth → S02 - Login (User) → Send

**Say:** "Login goes through Cognito and returns three tokens. The one we care about is the ID token — that's what carries the `custom:role` claim. The test script automatically saves it to an environment variable for the rest of the demo."

**Expected:** 200 with idToken in the response body.

### S02b — Login as admin

**Click:** Auth → S02b - Login (Admin) → Send

**Say:** "Same login flow for the admin user. We'll need both tokens for the role-based scenarios."

**Expected:** 200.

### S03 — Create a note (valid token)

**Click:** Notes CRUD → S03 - Create note (valid token) → Send

**Say:** "Now we're authenticated. We POST to /notes with the Authorization header set to Bearer plus the ID token. The authorizer verifies the token, looks up the role, sees that user role is allowed to POST /notes, returns Allow. The notes handler runs, creates the note, returns 201."

**Expected:** 201. Note the noteId in the response.

### S04 — Create note WITHOUT token

**Click:** Attacks → S04 - Create note WITHOUT token → Send

**Say:** "Now we strip the Authorization header. API Gateway sees no token and rejects with 401 before the request even reaches the authorizer Lambda."

**Expected:** 401.

> **Switch to the CloudWatch dashboard tab briefly.**

**Say:** "Notice the AuthFailures metric ticking up. Every denied request gets counted. If we hit 20 of these in 5 minutes, the high-auth-failures alarm fires and the team gets an email."

### S05 — Expired token

**Click:** Attacks → S05 - Expired token → Send

**Say:** "I captured this token over an hour ago. Cognito's default access token lifetime is one hour. The signature is still cryptographically valid — but the `exp` claim has passed."

**Expected:** 401.

> **If S05 was not pre-captured, skip this scenario. Say:** "We have a separate test for expired tokens that requires capturing one in advance — we'll show that in the test script output."

### S06 — DELETE as user role

**Click:** RBAC → S06 - DELETE as user (expect 403) → Send

**Say:** "Same valid token. Same authenticated user. But this time we're trying to DELETE. The role table says user role doesn't have DELETE permission on /notes/*. The authorizer matches the requested method against the role's permissions and returns Deny. 403 Forbidden."

**Expected:** 403.

### S07 — DELETE as admin role

**Click:** RBAC → Setup - Create admin note → Send (gets the note ID)
**Click:** RBAC → S07 - DELETE as admin (expect 200) → Send

**Say:** "Now using the admin token. Same endpoint, same operation — but admin role does have DELETE permission. The note is deleted. Note: data isolation still applies. An admin can only DELETE notes they own. The role gates whether DELETE is allowed at all, not whose data they can touch."

**Expected:** 200 or 204.

### S08 — Tampered token

**Click:** Attacks → S08 - Tampered token → Send

**Say:** "Pre-request script takes a valid token and flips the last character of the signature. The authorizer recomputes the expected signature against Cognito's public key, sees it doesn't match, rejects."

**Expected:** 401.

> **Optional callout — this is great content for the audience.**

**Say:** "Worth mentioning: during Phase 5 attack testing, this exact scenario caught a real bug in our deployment. The repo had correct verification code, but the deployed Lambda was running an older buggy version that approved tampered tokens. We caught it because the test was failing, dug into the CloudWatch logs, found the deployed code was stale, and redeployed. That's exactly what attack testing is for — finding the gap between what you think is deployed and what's actually running."

### S09 — Rate limiting

> **This takes ~20 seconds. Talk during the loop.**

**Click:** Switch to Postman Collection Runner. Select Rate Limiting → S10 - Rate limit GET. Set Iterations: 150, Delay: 0. Run.

**Say while it runs:** "We're sending 150 GET requests to /notes in rapid succession. Rate limit is set to 100 per minute per user. The first 100 should return 200, then everything after that returns 429."

**Expected:** ~99 200s, then ~50 429s starting around iteration 100.

**Say after it finishes:** "There's the cliff — request 100 succeeds, request 101 gets the 429. Notice the response body — that's our handler's structured rate-limit response, not API Gateway's default."

> **Switch to the CloudWatch dashboard.**

**Say:** "RateLimitHits metric just spiked. The rate-limit-spike alarm has a threshold of 50 in 5 minutes — we just blew past that. Email is on its way."

### S10 — The audit trail

> **Switch to the DynamoDB console, zerowall-audit-log table.**

**Click:** Items → Scan.

**Say:** "Every request the notes handler processed — allowed and denied — is recorded here. User ID, action, resource, source IP, result, status code, latency. This is the audit trail. If something went wrong during the demo, the answer is in this table."

### Anomaly checker live

> **Optional, depends on time. Strong content if there's room.**

**Click:** Lambda console → zerowall-anomaly-checker → Test → invoke.

**Say:** "The anomaly checker runs every 5 minutes on a schedule. It scans the audit log for patterns. After our rate-limit burst, it should detect a brute-force pattern for the test user. Let's invoke it manually to skip the wait."

> **Show the function logs. Find the JSON output with `findings`.**

**Say:** "There's the finding — BRUTE_FORCE pattern detected, severity high, denied count over threshold. That fires a notification to the SNS topic, and..."

> **Switch to email inbox. Refresh.**

**Say:** "There's the email."

---

## Closing (~30 seconds)

"To recap: every request hits the authorizer for JWT validation and RBAC, then the notes handler enforces rate limiting and writes an audit entry, and CloudWatch is watching the whole thing for anomalies. Each layer is independent — even if you compromise one, the others still verify. That's zero-trust applied at the API layer."

"The full repo is on GitHub. We have a setup guide that walks through deploying it from scratch in about 90 minutes, and a teardown script that takes everything down cleanly when you're done. Happy to take questions."

---

## Q&A prep

Likely questions and short answers:

**Q: Why JWT instead of session tokens?**
A: JWTs are stateless — the gateway can verify them without a database call to a session store. The role lookup hits DynamoDB but that's a single-row read. With caching off (TTL=0) we re-verify every request, which is the zero-trust posture.

**Q: How do you handle token rotation if Cognito rotates its signing keys?**
A: The authorizer caches the JWKS for 24 hours and refreshes if it sees an unknown `kid`. Cognito rotates rarely. If a rotation happens, the next unknown `kid` triggers an automatic refresh.

**Q: Isn't 100 requests per minute pretty low?**
A: Configurable via the `RATE_LIMIT_PER_MINUTE` env var on the notes handler. We set it low for demo purposes. In production you'd tune it per endpoint or per user tier.

**Q: What's the cost?**
A: Free tier covers everything we built — Lambda, DynamoDB on-demand, API Gateway, Cognito under 50k MAU, CloudWatch, SNS email under the free quota. The demo runs for free.

**Q: What about CSRF? XSS?**
A: Out of scope — those are browser-context attacks. ZeroWall is an API gateway, not a web app framework. We protect against API-layer attacks: missing auth, expired auth, role escalation, rate abuse, token tampering.

**Q: How would this scale?**
A: Lambda scales automatically. API Gateway has high default limits. DynamoDB on-demand scales seamlessly. The one weakness is the anomaly checker — it uses Scan, which is fine for this scale but would need to be redesigned (Query with GSIs, or stream-based) for production.

**Q: What's the one thing you'd change?**
A: The authorizer cache TTL. We set it to 0 so every request re-verifies. In production you'd want a short cache (30-60 seconds) for performance, but caching denied tokens for even a minute is dangerous. Probably the right answer is to cache only Allow decisions and re-verify Denies every time.

---

## Contingency plans

### If Postman won't connect

Most likely causes: the API URL has changed, or the auth handler is down. Fall back to the test script:

```bash
./scripts/test_attacks.sh
```

It exercises the same scenarios from the terminal. Walk through the output narration the same way you would in Postman.

### If S05 (expired token) wasn't pre-captured

Skip the scenario. Say: "We have an automated test for expired tokens that requires capturing one over an hour in advance — let me show you the script output instead." Show the test_attacks.sh summary table where S05 is marked PASS with the captured token, or SKIP with a clear message.

### If the rate-limit scenario doesn't trigger 429

Most likely cause: someone hit the API in the last minute and burned the user's window. Wait 60 seconds for the window to roll over, then re-run. Or use the admin user's token instead — different user, fresh window.

### If the SNS email doesn't arrive

Likely a Gmail filter caught it. Check spam folder. Worst case, show the alarm history in the CloudWatch console — the alarm did fire even if the email is in transit.

### If something is wildly broken

Pull up the test_attacks.sh terminal output from the most recent successful rehearsal and walk through it. The audit log in DynamoDB is also a strong fallback — every demo scenario leaves a paper trail there. You can reconstruct the demo from it.