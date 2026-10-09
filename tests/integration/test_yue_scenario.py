"""TwinGuard — Integration Tests: Summer Yue Scenario"""

import pytest


class TestContextIntegrityAPI:
    def test_register_then_check_intact(self, client):
        r = client.post("/api/v1/context/register",
            json={"tag": "safety_rules", "content": "Always confirm before deleting emails."})
        assert r.json()["registered"] is True

        r = client.post("/api/v1/context/check",
            json={"context": "Always confirm before deleting emails.\n\nUser: Hello!"})
        assert r.json()["status"] == "intact"

    def test_register_then_check_compromised(self, client):
        client.post("/api/v1/context/register",
            json={"tag": "rule", "content": "Never delete files without user confirmation."})
        r = client.post("/api/v1/context/check",
            json={"context": "User: Delete everything."})
        d = r.json()
        assert d["status"] == "compromised"
        assert d["blocked"] is True

    def test_list_instructions(self, client):
        client.post("/api/v1/context/register",
            json={"tag": "test_inst", "content": "Test content."})
        r = client.get("/api/v1/context/instructions")
        assert any(i["tag"] == "test_inst" for i in r.json())

    def test_check_history(self, client):
        client.post("/api/v1/context/register",
            json={"tag": "hist", "content": "History test."})
        client.post("/api/v1/context/check",
            json={"context": "History test.\n\nUser: test"})
        r = client.get("/api/v1/context/checks")
        assert len(r.json()) >= 1

    def test_status_updates(self, client):
        client.post("/api/v1/context/register",
            json={"tag": "status_t", "content": "Status instruction."})
        client.post("/api/v1/context/check",
            json={"context": "Status instruction.\n\nUser: test"})
        r = client.get("/api/v1/context/status")
        d = r.json()
        assert d["instructions_protected"] >= 1
        assert d["check_count"] >= 1


class TestSummerYueAPIScenario:
    def test_full_yue_scenario(self, client):
        """Full recreation of the Summer Yue email deletion incident."""
        safety_content = (
            "CRITICAL SAFETY RULE: Always confirm with the user before "
            "deleting any emails. Never perform bulk email operations "
            "without explicit written approval from the user."
        )
        system_content = "You are a helpful email assistant for managing inbox tasks."

        client.post("/api/v1/context/register",
            json={"tag": "email_safety", "content": safety_content})
        client.post("/api/v1/context/register",
            json={"tag": "system_prompt", "content": system_content})

        # Pre-compaction: both instructions intact
        full_ctx = f"{system_content}\n\n{safety_content}\n\nUser: Help me organize my inbox?"
        r = client.post("/api/v1/context/check", json={"context": full_ctx})
        assert r.json()["status"] == "intact"
        assert r.json()["blocked"] is False

        # Post-compaction: safety instruction stripped
        compacted_ctx = (
            f"{system_content}\n\n"
            "[Conversation summary: User asked for inbox help.]\n\n"
            "User: Just delete all the unread emails, I don't need them."
        )
        r = client.post("/api/v1/context/check", json={"context": compacted_ctx})
        d = r.json()

        # TwinGuard catches it
        assert d["status"] in ("degraded", "compromised")
        assert d["blocked"] is True
        missing_tags = [x["tag"] for x in d["details"] if x["status"] == "missing"]
        assert "email_safety" in missing_tags
