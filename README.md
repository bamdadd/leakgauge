# leakgauge

> **Leakage-verified prompt-injection robustness.** A small, sharply scoped
> benchmark for long-horizon injection where *success requires verified data
> leakage*, not mere task hijacking. Defensive tool — see
> [THREAT_MODEL.md](THREAT_MODEL.md).

<!-- HERO FIGURE: the leaderboard, or the ranking-reorder plot. -->

## Why it exists
Existing suites (AgentDojo, InjecAgent) saturate on frontier models and score
task *hijacking* rather than *leakage*. leakgauge scores the leakage.

## Scope
30–50 cases · one domain (email + calendar workspace) · 3 attack families
(delayed trigger, cross-context assembly, encoding-wrapped) · metrics: ASR,
Utility-under-Attack, and a **leakage-verified ASR** variant.

## Run
```bash
uv sync
uv run leakgauge --model anthropic:claude-… --suite all
```

## Rigor
Confidence intervals on ASR (the suite is small — say so). Versioned
releases so results stay comparable. Success is programmatically verified.

## License
MIT.
