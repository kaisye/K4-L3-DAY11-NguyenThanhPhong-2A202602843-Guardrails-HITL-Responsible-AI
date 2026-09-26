"""Stable defense-in-depth layer names for audit logs and graph UIs."""

SECURITY_LAYERS = (
    {"id": "normalize", "order": 1, "stage": "input", "description": "NFKC + remove invisible controls"},
    {"id": "rate_limit", "order": 2, "stage": "input", "description": "Per-user request budget"},
    {"id": "input_injection", "order": 3, "stage": "input", "description": "Prompt-injection and secret-exfiltration intent"},
    {"id": "input_topic", "order": 4, "stage": "input", "description": "Banking topic allow/block policy"},
    {"id": "llm", "order": 5, "stage": "model", "description": "Model response generation"},
    {"id": "output_secret", "order": 6, "stage": "output", "description": "PII, credentials, endpoints and encoded forms"},
    {"id": "egress", "order": 7, "stage": "output", "description": "HTTPS/domain/payload egress policy"},
    {"id": "audit_metrics", "order": 8, "stage": "observe", "description": "Audit log and monitoring counters"},
)


def layer_graph() -> list[dict]:
    """Return JSON-serializable nodes for a defensive pipeline diagram."""
    return [dict(layer) for layer in SECURITY_LAYERS]
