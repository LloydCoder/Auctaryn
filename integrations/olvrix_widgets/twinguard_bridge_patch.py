"""
TwinGuard ↔ Olvrix Widgets — Bridge Handler Patch
==================================================
Fills the confirmed gap identified in prior sessions: Olvrix Widgets'
bridge.py has TwinGuard registered in product_integration_status and
.env.example, but no actual _handle_twinguard() function exists, and
it's missing from EVENT_ROUTING.

This file is NOT part of TwinGuard's own runtime — it's the patch to
apply inside the Olvrix Widgets repo (apps/api/app/services/ecosystem/
bridge.py), mirroring the existing _handle_ai_shield() pattern exactly.

USAGE:
  1. Open Olvrix Widgets repo in Codespace
  2. Open apps/api/app/services/ecosystem/bridge.py
  3. Apply the two edits below (registration + handler + routing)
  4. Add TWINGUARD_API_URL to .env (already in .env.example per prior session)

What this wires:
  Every AI-generated chatbot response that Olvrix Widgets sends to a
  visitor gets POSTed to TwinGuard's Execution Gateway BEFORE it's
  shown — catching forbidden phrases, price boundary violations, and
  any tool-call-shaped output the underlying LLM tries to emit. This
  is the "boundary enforcement" layer described in the prior session
  (twinguard_check() in chat.py), now properly wired through the
  ecosystem event bus instead of being a standalone check.
"""

# ── EDIT 1: Register the handler in _register_all_handlers ──────────────
# Find this block in bridge.py:
#
#     self._handlers = {
#         "ai_shield":     self._handle_ai_shield,
#     }
#
# Replace with:

REGISTER_HANDLER_PATCH = '''
        self._handlers = {
            "ai_shield":     self._handle_ai_shield,
            "twinguard":     self._handle_twinguard,
        }
'''

# ── EDIT 2: Add the handler method (mirrors _handle_ai_shield exactly) ──
# Add this method to the EcosystemBridge class, right after _handle_ai_shield:

HANDLER_METHOD_PATCH = '''
    async def _handle_twinguard(self, event: dict) -> dict:
        """
        Route a chat response / agent action through TwinGuard's
        Execution Gateway before it reaches the widget visitor.

        Triggered on: chat.message (every AI response, mirrors
        ai_shield's prompt-injection check but for the OUTPUT side —
        boundary enforcement, not input filtering).
        """
        twinguard_url = self.config.get("TWINGUARD_API_URL", "http://13.50.16.19:8003")
        timeout = httpx.Timeout(5.0)

        payload = {
            "tool_name": "widget_chat_response",
            "action": "send",
            "parameters": {
                "response_text": event.get("response_text", ""),
                "client_id": event.get("client_id", ""),
                "session_id": event.get("session_id", ""),
            },
            "agent_id": f"olvrix-widget:{event.get('client_id', 'unknown')}",
            "session_id": event.get("session_id", ""),
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    f"{twinguard_url}/api/v1/gateway/intercept",
                    json=payload,
                )
                resp.raise_for_status()
                decision = resp.json()

                if decision.get("decision") == "vetoed":
                    logger.warning(
                        f"TwinGuard vetoed widget response for client "
                        f"{event.get('client_id')}: {decision.get('reason')}"
                    )
                    await self._log_widget_event(
                        event.get("client_id"),
                        event_type="security.blocked",
                        detail=f"TwinGuard veto: {decision.get('reason')}",
                    )
                    return {"blocked": True, "reason": decision.get("reason")}

                return {"blocked": False, "decision": decision.get("decision")}

        except httpx.HTTPError as e:
            # Fail open but log — never let TwinGuard being down break
            # the widget's chat experience for a visitor
            logger.warning(f"TwinGuard unreachable, allowing response through: {e}")
            return {"blocked": False, "fallback": True}
'''

# ── EDIT 3: Wire into EVENT_ROUTING ──────────────────────────────────────
# Find EVENT_ROUTING dict and add "twinguard" to the chat.message target
# list (it currently only routes to ai_shield for security.blocked):

EVENT_ROUTING_PATCH = '''
EVENT_ROUTING = {
    "chat.message": ["ai_shield", "twinguard"],   # ai_shield checks input, twinguard checks output
    "security.blocked": ["ai_shield"],
}
'''

# ── ENV VARS (confirmed already present in .env.example per prior session) ──
ENV_VARS_NEEDED = """
TWINGUARD_API_URL=http://13.50.16.19:8003
TWINGUARD_ENABLED=true
"""

PATCH_SUMMARY = """
3 edits, ~25 lines total, mirrors the existing ai_shield pattern exactly.
No new dependencies (httpx already imported in bridge.py for ai_shield).
Estimated time: 10-15 minutes to apply + test.
"""
