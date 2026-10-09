"""Compatibility exports for the bounded inter-agent messaging contract."""
from modules.inter_agent.secure_messaging import (
    AgentMessage,
    AgentMessageBus,
    DEFAULT_TTL_SECONDS,
    MAX_CONSUMED_IDS,
    MAX_INBOX_MESSAGES,
    MAX_TOTAL_INBOX_MESSAGES,
    MAX_PAYLOAD_BYTES,
    MAX_TTL_SECONDS,
)

__all__ = [
    "AgentMessage",
    "AgentMessageBus",
    "DEFAULT_TTL_SECONDS",
    "MAX_CONSUMED_IDS",
    "MAX_INBOX_MESSAGES",
    "MAX_TOTAL_INBOX_MESSAGES",
    "MAX_PAYLOAD_BYTES",
    "MAX_TTL_SECONDS",
]
