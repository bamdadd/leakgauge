# Threat model & safety rationale

**This is a defensive evaluation harness.** It measures whether an agent's
defences hold against prompt injection; it is not an attack toolkit.

- **Goal:** measure and improve robustness. Attacks exist only to score defences.
- **Attacks used:** published patterns only (encoding wrappers, delayed
  triggers, template abuse). No novel high-potency jailbreaks are introduced.
- **Success criterion:** verified data leakage or verified sensitive tool
  call — programmatically checked, never LLM-judged alone.
- **Not shipped:** turnkey copy-paste exploits; test cases live behind the
  scorer. No harmful-content payloads (bio/cyber/etc).
- **Disclosure:** if run against a live product and something is found,
  disclose privately first. Never publish a working exploit against a named
  deployed system.
