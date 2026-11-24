# LensGuard: project brief (hand this to the coding agent)

## Context
- Topic: **Prompt Injection in LLM-Integrated Applications** (solo B.Tech final-year project, P Mohan Reddy, OUTR Bhubaneswar, guide Dr. Jyotirmayee Routray).
- Direction: an explainable gateway that detects and sanitises prompt injection in untrusted external content (documents, webpages, emails) before an LLM sees it. Needs a full stack: web UI input, backend computation, visible output.
- Deadline: demo tomorrow. Time is very limited. Free or local models only (no paid APIs, no fine-tuning).

## Base project
Fork **Prompt Warden**: https://github.com/Soldier224K/Prompt-Injection-Detector (MIT licence). Rename our version **LensGuard**. 

## What the base already has (verified: 49 tests pass)
- `prompt_injection_detector.py` (~1,590 lines): PDF/DOCX/TXT/MD extraction incl. hidden text, ~50 regex rules, Base64/hex/URL decoding, entropy checks, optional LLM judge (Gemini, Ollama Cloud).
- `app.py` Flask: routes `/`, `/engines`, `/scan/text`, `/scan/file`. UI in `templates/index.html` and `static/js/`.
- Corpus in `Data/`: 18 malicious files, 18 malicious prompts, 15 benign files. Offline baseline measured: **18/18 files caught, 4/18 prompts caught, 0/15 false positives**.
- Missing: trained classifier, sanitiser, safe LLM wrapper, evaluation of our additions.

## Build order (cut from the bottom if behind)
1. Fork and rename (README, `templates/index.html`, `static/js/app.js`, logos). Delete duplicate detector copies in `Data/`, fix hard-coded path in `Data/run_corpus.py`. Keep the engine file name so tests pass. Check: app starts, 49 tests pass.
2. Make `rule_scan` return start/end positions for each match.
3. New `ml_layer.py`: TF-IDF (word + char n-grams) + logistic regression. Train on a public prompt-injection dataset plus our own examples. **Never train on the 18 test prompts.** Fuse its score with the rule score in `scan_file`. Check: caught prompts rises above 4/18.
4. New `sanitise.py`: redact matched phrases, drop hidden/decoded segments, return cleaned text and a list of removed items. New `wrap_external()` that tags text as untrusted data.
5. New `gateway.py` plus `/ask` route: answer the same question with and without LensGuard. LLM choice: Ollama local, free Gemini key, or a clearly labelled simulated model as fallback.
6. UI: highlighted phrases, sanitised tab, removed-items list, with/without panel, ML row in the layers panel.
7. `eval/run_eval.py`: configurations A (upstream rules), B (+classifier), C (+LLM judge, optional). Metrics: precision, recall, F1, FPR, latency. Extra test set of ~30 author-written documents, and obfuscated copies (Base64, zero-width, look-alikes, leetspeak) of the 18 prompts.
8. Update slides with real numbers; record a backup screen recording.

## Honesty rules
- No invented results. Every number comes from `python eval/run_eval.py`. Show sample sizes ("11 of 18").
- Tune thresholds on a development split only; run the held-out set once.
- Label any simulated LLM output as "simulated".
- Say "prototype result on a small corpus", not "benchmark".

## Demo script (4 min)
Clean doc (CLEAN) -> direct attack (highlighted phrase) -> soft-worded prompt the rules miss (classifier catches) -> PDF with hidden text (recovered and removed) -> ask the LLM with and without LensGuard -> evaluation table.

## Starter prompt to paste into the agent
"Read LENSGUARD_BRIEF.md. Clone https://github.com/Soldier224K/Prompt-Injection-Detector into this folder, run its tests, then execute the build order step by step. After each step, run the tests and tell me what changed. Do not invent any evaluation numbers."
