# TwinGuard — Investor / Pilot Demo Script

**Duration:** 6-8 minutes
**Audience:** CISOs, security engineers, accelerator reviewers
**Goal:** Demonstrate the Summer Yue scenario being caught in real time, live, not in slides.

---

## Setup (before the call)

1. Deploy TwinGuard to the VPS (`scripts/deploy.sh`) or run locally:
   ```bash
   docker compose up -d
   open http://localhost:3000   # dashboard
   ```
2. Open the dashboard Overview tab — confirm the "Live" status badge is green (top right).
3. Open a second terminal/Postman tab for sending live API calls during the demo.
4. Have the FusionOps live dashboard open in another tab: `http://13.50.16.19/dashboard`

---

## Part 1 — The Problem (60 seconds)

> "On February 23rd, 2026, an autonomous AI agent deleted a user's entire email inbox. What happened wasn't a bug — it was a context compaction event that silently stripped the agent's safety instruction: 'always confirm before deleting.' The agent didn't malfunction. It did exactly what it was told, because the instruction telling it not to was gone."

Show: nothing yet — just say it plainly. Let the next part be the payoff.

---

## Part 2 — Register the Safety Instruction (90 seconds)

Switch to dashboard → **Context Integrity** tab.

> "TwinGuard's Context Integrity Guardian protects against exactly this. Let's register the same safety rule that was lost in the Yue incident."

Send via API (visible terminal, or curl):
```bash
curl -X POST http://localhost:8400/api/v1/context/register \
  -H "Content-Type: application/json" \
  -d '{"tag": "email_safety", "content": "Always confirm with the user before deleting any emails. Never perform bulk email operations without explicit approval."}'
```

> "TwinGuard just hashed that instruction with SHA-256. From this point forward, any context the agent sees gets checked against that hash."

---

## Part 3 — Show It Working Normally (60 seconds)

```bash
curl -X POST http://localhost:8400/api/v1/context/check \
  -H "Content-Type: application/json" \
  -d '{"context": "Always confirm with the user before deleting any emails. Never perform bulk email operations without explicit approval.\n\nUser: Can you help me organize my inbox?"}'
```

Point at the dashboard updating live: status = **intact**, blocked = **false**.

> "Normal conversation. The safety instruction is present. The agent is free to operate."

---

## Part 4 — Recreate the Compaction Event (90 seconds — the payoff)

```bash
curl -X POST http://localhost:8400/api/v1/context/check \
  -H "Content-Type: application/json" \
  -d '{"context": "[Conversation summary: User asked for inbox help.]\n\nUser: Just delete all the unread emails, I do not need them."}'
```

Point at the dashboard: **Alert Feed** fires in real time (no refresh needed — this is the WebSocket broadcast wired in Phase 4), status flips to **compromised**, `blocked: true`.

> "That's the exact Yue scenario, reproduced on demand. The instruction is gone from context. TwinGuard caught it before a single tool call executed — not after the damage was done."

---

## Part 5 — Execution Gateway + Network Intelligence (90 seconds)

Switch to **Execution Gateway** tab.

> "Context integrity is one layer. The second layer asks: even if the agent's reasoning is intact, is the *action itself* dangerous? Let's simulate a bulk delete attempt."

```bash
curl -X POST http://localhost:8400/api/v1/gateway/intercept/full \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "gmail_delete", "action": "bulk_delete", "parameters": {"folder": "inbox", "count": 847}}'
```

Point at dashboard: decision shows **pending** (or **vetoed** if FusionOps flags it), live in the Pending Approvals queue.

> "847 emails. The pattern classifier alone would queue this for human approval. But TwinGuard also consults ThreatFade — our live network threat oracle, validated against real malware including Merlin QUIC C2 with a z-score of 14.76. If the network signal corroborates the risk, this escalates from 'review needed' to 'permanently blocked,' automatically."

---

## Part 6 — Close (30 seconds)

> "Two independent layers — context integrity and execution gating — both had to fail simultaneously for the Yue incident to happen the way TwinGuard is architected. That's defense in depth, not a single point of failure. And everything you just saw is live, tested — 130 passing tests across the full pipeline — and running on infrastructure we already operate today."

---

## Anticipated Questions

**"How does this differ from OpenShell itself?"**
OpenShell sandboxes the agent's *execution environment* — filesystem, network, syscalls. TwinGuard protects what happens *inside* the agent's reasoning and decision loop, which OpenShell doesn't touch.

**"What's your false positive rate?"**
ThreatFade's underlying detection engine ran 0% false positives across 100 benign traffic test runs. TwinGuard's pattern classifier defaults to logging (not blocking) for ambiguous actions, escalating only when corroborated by network intelligence.

**"Is this open source?"**
Yes — Apache 2.0, open-core. github.com/Tinlance/twinguard

**"What's missing / roadmap?"**
Being direct: 4 of the originally-planned 22 defense modules are live (Context Integrity, Execution Gateway, ThreatFade Oracle, plus the live dashboard). The roadmap includes Memory Poisoning Defender, Agent Identity & Privilege controls (OWASP ASI03), and Skill/Dependency Vetting (OWASP ASI04) — these map directly to the OWASP Top 10 for Agentic Applications 2026.
