# Auctaryn API authorization matrix

## Authority rule

Auctaryn's service credential authenticates a service caller; it does not identify a human operator or establish a tenant. The administrator credential is a distinct bootstrap credential and is not a replacement for enterprise SSO/MFA. Tinlance Agent Platform remains authoritative for tenant identity, capability authorization, approvals and consequential execution.

| API surface | Service credential | Administrator credential | Additional enforcement |
|---|---|---|---|
| `/api/v1/risk/assess` | Allowed | Allowed | Advisory-only response; no allow/deny or execution grant |
| `/api/v1/gateway/evaluate`, `/intercept`, `/intercept/full` | Allowed | Allowed | Gateway policy, scoped agent token and context checks where configured |
| `/api/v1/gateway/decisions*`, `/pending`, `/approve` | Denied | Allowed | Decisions/history and approvals are privileged |
| `/api/v1/identity/*` | Denied | Allowed | Local identity manager is not Platform identity authority |
| `/api/v1/context/checks*`, `/compactions`, `/instructions*`, `/sessions/*`, `/register` | Denied for administrative state | Allowed | Context state may contain protected policy metadata |
| `/api/v1/skills/history`, publisher trust and known-skill registry | Denied for history/trust mutation | Allowed | Artifact evaluation remains advisory |
| `/api/v1/evidence/*`, `/api/v1/incident/*`, memory quarantine | Denied | Allowed | Forensic and containment controls |
| `/api/v1/memory/*` agent operations | Allowed with scoped agent token | Allowed | Agent/session binding, quarantine and integrity checks |
| `/api/v1/gateway/execute*` | Denied | Denied by default; admin only when explicitly enabled | `AUCTARYN_ALLOW_DIRECT_EXECUTION=true` required |
| `/ws/actions` and `/ws/alerts` | Limited stream role | Operator actions/incident alerts | Origin checks and first-frame credential authentication |

## Deployment rules

1. The advisory risk request rejects unknown fields, including caller-supplied `tenant_id`; tenant identity must come from Platform-authenticated context, not the request body.
2. Keep service and administrator credentials distinct and rotate them through the deployment secret manager.
3. Leave `AUCTARYN_ALLOW_DIRECT_EXECUTION` unset in the Platform-integrated production profile.
4. Use the Platform's authenticated principal to bind tenant, subject, agent, intent, policy and approval. Do not trust request-body or caller-supplied tenant identifiers.
5. Static service/admin credentials do not provide per-human attribution, tenant isolation or MFA. Use a Platform-side adapter and enterprise identity provider for those properties.
6. Route-level negative authorization tests are required whenever the API surface changes.
