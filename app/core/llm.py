"""
Hook for Phase 1.5+: Given evidence.json, call an LLM to produce a narrative.
We keep this isolated to protect privacy and make it easy to disable.
"""
class LLMNotConfigured(Exception):
    pass


def generate_narrative_with_llm(evidence: dict) -> str:
    raise LLMNotConfigured("No LLM configured in Phase 1; using rule-based report instead.")
