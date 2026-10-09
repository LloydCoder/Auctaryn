"""
Auctaryn ↔ Olvrix Widgets — integration contract (draft)
========================================================

This file is a reference patch for the separate Olvrix Widgets repository. It is
not part of Auctaryn's runtime and has not been validated against that repository.

Important boundary:
- Auctaryn's Execution Gateway is for agent actions, not generic LLM text moderation.
- Do not route every ordinary `chat.message` through an action-decision endpoint.
- Route only consequential `agent.action` events whose tool/action/parameters are
  meaningful to the gateway's policy model.
- The caller must suppress the action unless the returned decision is exactly
  `approved`. Pending, denied, vetoed, malformed, unauthenticated, or unavailable
  responses all fail closed.
- The service API key and short-lived scoped agent token are separate credentials.
  In production, retrieve/rotate the agent token through Tinlance Agent Platform;
  do not hardcode it in source control.
- Auctaryn does not automatically mediate other paths. The host application must
  prove that every consequential action uses this handler before enabling it.

Before adapting this patch, complete Platform identity/token integration, pass
Auctaryn's OpenShell live acceptance procedure, and add integration tests in the
Olvrix Widgets repository.

REQUIRED IMPORTS in the host bridge:
    from urllib.parse import urlparse
    import httpx

CONFIGURATION:
    AUCTARYN_API_URL=https://<verified-host>
    AUCTARYN_API_KEY=<service credential from secret manager>
    AUCTARYN_AGENT_ID=<registered agent ID>
    AUCTARYN_AGENT_TOKEN=<short-lived scoped agent token from Platform>
"""

# EDIT 1: Register a handler for consequential agent actions, not all chat text.
REGISTER_HANDLER_PATCH = """
        self._handlers = {
            "ai_shield": self._handle_ai_shield,
            "auctaryn": self._handle_auctaryn_action,
        }
"""

# EDIT 2: Add this method to the host EcosystemBridge class.
HANDLER_METHOD_PATCH = r'''
    async def _handle_auctaryn_action(self, event: dict) -> dict:
        """Gate a consequential agent action; never treat an outage as approval."""
        from urllib.parse import urlparse

        base_url = str(self.config.get("AUCTARYN_API_URL", "")).rstrip("/")
        service_key = self.config.get("AUCTARYN_API_KEY", "")
        agent_id = self.config.get("AUCTARYN_AGENT_ID", "")
        agent_token = self.config.get("AUCTARYN_AGENT_TOKEN", "")
        session_id = event.get("session_id", "")
        context_check_id = event.get("context_check_id", "")

        if not all(isinstance(value, str) and value.strip() for value in (
            base_url, service_key, agent_id, agent_token, session_id, context_check_id
        )):
            logger.error("Auctaryn integration configuration or session evidence is missing")
            return {"blocked": True, "reason": "security_configuration_missing"}

        parsed = urlparse(base_url)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and parsed.hostname not in local_hosts:
            logger.error("Auctaryn integration refused a non-HTTPS remote endpoint")
            return {"blocked": True, "reason": "insecure_security_endpoint"}

        # Map only trusted server-side action metadata. Never trust a client-supplied
        # agent ID, identity token, or context-check ID without upstream validation.
        payload = {
            "tool_name": str(event.get("tool_name", "")),
            "action": str(event.get("action", "")),
            "parameters": event.get("parameters", {}),
            "agent_id": agent_id,
            "session_id": session_id,
            "context_check_id": context_check_id,
            "identity_token": agent_token,
        }
        if not payload["tool_name"] or not payload["action"] or not isinstance(payload["parameters"], dict):
            return {"blocked": True, "reason": "invalid_action_envelope"}

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                response = await client.post(
                    f"{base_url}/api/v1/gateway/intercept",
                    headers={"Authorization": f"Bearer {service_key}"},
                    json=payload,
                )
                response.raise_for_status()
                decision = response.json()
                if not isinstance(decision, dict) or decision.get("decision") != "approved":
                    logger.warning("Auctaryn did not approve the action; suppressing it")
                    return {
                        "blocked": True,
                        "reason": "action_not_approved",
                        "decision": decision.get("decision") if isinstance(decision, dict) else "invalid_response",
                    }
                return {"blocked": False, "decision": "approved"}
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("Auctaryn decision unavailable; suppressing action (%s)", type(exc).__name__)
            return {"blocked": True, "reason": "security_service_unavailable"}
'''

# EDIT 3: Route consequential action events through Auctaryn.
# Do not attach Auctaryn to every ordinary chat.message event as a substitute
# for content moderation; that is a different policy and execution contract.
EVENT_ROUTING_PATCH = """
EVENT_ROUTING = {
    "agent.action": ["auctaryn"],
    "security.blocked": ["ai_shield"],
}
"""

PATCH_SUMMARY = """
Draft integration contract only. It requires a real host-repository implementation,
a registered agent, a scoped short-lived token, current context-check evidence,
TLS for remote endpoints, and end-to-end tests proving non-approved actions are
never forwarded. Do not deploy until those acceptance criteria pass.
"""
