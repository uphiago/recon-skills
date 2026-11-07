---
name: hunt-metrics-exposure
description: "Hunt public /metrics, /health, and actuator endpoints leaking AI usage, DB pools, and operational intelligence."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [metrics, exposure, hunt, redteam]
---

## When to Use

The target uses modern observability tooling (Go, .NET, Java, Node.js). These frameworks often expose `/metrics`, `/health`, and `/status` endpoints that are forgotten behind auth. Unlike application data leaks, metrics leaks reveal the ENTIRE operational profile: which AI models are used, how many users are active, database connection exhaustion, and third-party service dependencies.

---

## Phase 1 — Discover Metrics Endpoints

```bash
TARGET="https://target.com"

# Common observability paths
for ep in metrics health status ready live readyz healthz \
  actuator/health actuator/metrics actuator/prometheus \
  Telescope telescope horizon debug; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /tmp/metrics_${ep}.txt -w "%{http_code}" \
    "${TARGET}/${ep}" 2>/dev/null)
  if [ "$code" = "200" ]; then
    size=$(wc -c < /tmp/metrics_${ep}.txt)
    echo "  /${ep}: HTTP 200 (${size} bytes)"
  fi
done
```

---

## Phase 2 — Analyze Prometheus Metrics

```bash
# Count unique metric families (each reveals a subsystem)
grep -c '^# HELP' /tmp/metrics_metrics.txt

# Extract AI/ML model usage
grep -i 'ai_\|model\|llm\|openai\|gemini\|copilot' /tmp/metrics_metrics.txt

# Extract database pool states
grep -i 'db_pool\|database\|connection' /tmp/metrics_metrics.txt

# Extract third-party dependencies
grep -i 'stripe\|openai\|sendgrid\|twilio\|email' /tmp/metrics_metrics.txt

# Extract request volumes (user activity)
grep -i 'http_request\|api_request\|grpc_request' /tmp/metrics_metrics.txt

# Extract circuit breaker states (service health)
grep -i 'circuit_breaker' /tmp/metrics_metrics.txt
```

---

## Phase 3 — Analyze Health/Status Endpoints

```bash
# Spring Boot Actuator
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/health" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/metrics" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/env" | python3 -m json.tool  # May leak env vars

# Custom health endpoints
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/health" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/api/health" | python3 -m json.tool

# Laravel Telescope (if exposed)
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/telescope/requests" | head -c 500
```

---

## What Metrics Reveal

| Metric | Intelligence Gained |
|--------|-------------------|
| `ai_analyzer_output_total{model="gpt-5-mini"}` | Which AI models are used, usage volume |
| `db_pool_idle_connections{pool="api"}` | Database pool sizing, connection exhaustion risk |
| `circuit_breaker_state{client="stripe"}` | Third-party dependencies and their health |
| `clinical_copilot_sse_active` | Real-time user count for specific features |
| `http_requests_total` | Request volume, peak hours, user activity |
| `app_version` / `build_info` | Deployed version, build timestamps |

---

## Verification

- **Confirmed exposure**: `/metrics` returns Prometheus text format (lines starting with `# HELP` or `# TYPE`)
- **Actuator exposure**: `/actuator/health` returns JSON with component statuses
- **False positive**: Endpoint returns `{"status":"ok"}` only (minimal health check, not a metrics leak)
- **Severity upgrade**: `/actuator/env` or `/actuator/configprops` exposed → HIGH/CRITICAL only if the response contains unredacted secrets (Spring Boot 2.2+ redacts `password`/`secret`/`key` values by default — check the body before scoring)

---

## What Next

- AI model usage metrics → pivot to `hunt-llm-ai` (prompt injection on discovered models)
- DB pool metrics showing overload → DoS attack surface identified
- Circuit breaker states for Stripe/email → infrastructure dependency map for chained attacks
- Combine with `hunt-schema-enumeration` for full target profile

---

## Pitfalls
- **Prometheus /metrics without secrets** — metrics endpoints exposing request counts are informational. Need labels containing PII, internal hostnames, or credentials.
- **Spring Boot Actuator /actuator/metrics** — metrics are intentionally exposed for monitoring. Only report if they leak sensitive data (usernames in labels, internal IPs).
- **JMX without auth** — JMX exposure without authentication is critical only if write operations (MBean invocation) are possible. Read-only JMX is informational.
- **Health endpoint without sensitive data** — `/health`, `/status`, `/ready` endpoints are designed to be public. Need leaked internal data.
