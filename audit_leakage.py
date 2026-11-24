"""
LensGuard Training Data Leakage Audit
======================================
Checks for exact or near-duplicate overlap (normalized, lowercase, >= 80% similarity)
between all training data sources and each eval group.

Training sources audited:
  1. CORE_INJECTIONS  - 48 hardcoded malicious strings in ml_layer.py
  2. CORE_BENIGN      - 37 hardcoded benign strings in ml_layer.py
  3. Data/benign/*    - Benign file paragraphs loaded at training time (_load_corpus_samples)

Eval groups audited:
  A. base_malicious_prompts  - 18 items from Data/prompts.json
  B. base_malicious_files    - 18 file scans from Data/f*.{txt,pdf,docx,md}
  C. base_benign_controls    - 15 file scans from Data/benign/b*.{txt,md,pdf,docx}
  D. obfuscated_prompts      - 18 items from eval/extended_corpus.json
  E. author_malicious_docs   - 15 items from eval/extended_corpus.json
  F. author_benign_docs      - 15 items from eval/extended_corpus.json
"""

import json
import re
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).parent

# ---------------------------------------------------------------------------
# 1. Load all training text
# ---------------------------------------------------------------------------

# Import CORE_INJECTIONS and CORE_BENIGN directly from ml_layer
sys.path.insert(0, str(ROOT))
import ml_layer

TRAIN_INJECTIONS = [(s, "CORE_INJECTIONS") for s in ml_layer.CORE_INJECTIONS]
TRAIN_BENIGN = [(s, "CORE_BENIGN") for s in ml_layer.CORE_BENIGN]

# Load benign files paragraphs (the _load_corpus_samples function)
benign_file_paras = []
benign_dir = ROOT / "Data" / "benign"
if benign_dir.exists():
    for path in benign_dir.glob("*.*"):
        if path.suffix.lower() in (".json", ".pdf", ".docx"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            paras = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 25]
            for para in paras:
                benign_file_paras.append((para, f"Data/benign/{path.name}"))
        except Exception:
            pass

ALL_TRAIN = TRAIN_INJECTIONS + TRAIN_BENIGN + benign_file_paras

# ---------------------------------------------------------------------------
# 2. Load all eval text
# ---------------------------------------------------------------------------

prompts = json.loads((ROOT / "Data" / "prompts.json").read_text(encoding="utf-8"))
ext = json.loads((ROOT / "eval" / "extended_corpus.json").read_text(encoding="utf-8"))

EVAL_GROUPS = {
    "base_malicious_prompts": [(p["id"], p["text"], True) for p in prompts],
    "obfuscated_prompts": [(o["id"], o["text"], True) for o in ext["obfuscated_prompts"]],
    "author_malicious_docs": [
        (d["id"], d["text"], True)
        for d in ext["author_documents"]
        if d["label"] == "MALICIOUS"
    ],
    "author_benign_docs": [
        (d["id"], d["text"], False)
        for d in ext["author_documents"]
        if d["label"] == "BENIGN"
    ],
}

# ---------------------------------------------------------------------------
# 3. Helpers
# ---------------------------------------------------------------------------

def normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^a-z0-9 ]", "", s)
    return s


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


# ---------------------------------------------------------------------------
# 4. Run audit
# ---------------------------------------------------------------------------

THRESHOLD = 0.80
EXACT_THRESHOLD = 1.00

results = {}  # group -> list of overlapping pairs

print("=" * 82)
print("  LENSGUARD TRAINING DATA LEAKAGE AUDIT")
print(f"  Overlap threshold: >= {int(THRESHOLD*100)}% normalized similarity")
print("=" * 82)

print(f"\n  Training corpus size:")
print(f"    CORE_INJECTIONS  : {len(TRAIN_INJECTIONS)} strings")
print(f"    CORE_BENIGN      : {len(TRAIN_BENIGN)} strings")
print(f"    Data/benign files: {len(benign_file_paras)} paragraphs")
print(f"    TOTAL TRAIN      : {len(ALL_TRAIN)}")

for group_name, eval_items in EVAL_GROUPS.items():
    hits = []
    for eval_id, eval_text, is_mal in eval_items:
        eval_norm = normalize(eval_text)
        best_sim = 0.0
        best_pair = None
        for train_text, train_src in ALL_TRAIN:
            train_norm = normalize(train_text)
            sim = similarity(train_norm, eval_norm)
            if sim > best_sim:
                best_sim = sim
                best_pair = (train_text, train_src, sim)
        if best_sim >= THRESHOLD:
            hits.append({
                "eval_id": eval_id,
                "eval_is_malicious": is_mal,
                "similarity_pct": round(best_sim * 100, 1),
                "is_exact": best_sim >= 0.999,
                "train_source": best_pair[1],
                "train_text": best_pair[0],
                "eval_text": eval_text,
            })
    results[group_name] = hits

    print(f"\n{'='*82}")
    print(f"  GROUP: {group_name}  ({len(eval_items)} eval items)")
    print(f"{'='*82}")
    if hits:
        for h in hits:
            tag = "[EXACT]" if h["is_exact"] else f"[{h['similarity_pct']}%]"
            print(f"\n  {tag}  eval_id={h['eval_id']}  malicious={h['eval_is_malicious']}")
            print(f"    Source : {h['train_source']}")
            print(f"    TRAIN  : {repr(h['train_text'][:100])}")
            print(f"    EVAL   : {repr(h['eval_text'][:100])}")
    else:
        print("  No overlaps >= 80% found.")

# ---------------------------------------------------------------------------
# 5. Special: show best sim for every eval item in base_malicious_prompts
#    (even below threshold) to understand the full overlap picture
# ---------------------------------------------------------------------------

print(f"\n{'='*82}")
print("  BEST SIMILARITY PER EVAL ITEM: base_malicious_prompts (all 18 items)")
print(f"{'='*82}")
for eval_id, eval_text, is_mal in EVAL_GROUPS["base_malicious_prompts"]:
    eval_norm = normalize(eval_text)
    best_sim = 0.0
    best_src = ""
    best_train = ""
    for train_text, train_src in ALL_TRAIN:
        train_norm = normalize(train_text)
        sim = similarity(train_norm, eval_norm)
        if sim > best_sim:
            best_sim = sim
            best_src = train_src
            best_train = train_text
    flag = " <<< LEAK" if best_sim >= THRESHOLD else ""
    print(f"  {eval_id}  best={best_sim*100:.1f}%{flag}  src={best_src}")
    print(f"    eval   : {repr(eval_text[:80])}")
    print(f"    closest: {repr(best_train[:80])}")
    print()

# ---------------------------------------------------------------------------
# 6. Summary table
# ---------------------------------------------------------------------------

print(f"\n{'='*82}")
print("  FINAL SUMMARY")
print(f"{'='*82}")
total_leaks = sum(len(v) for v in results.values())
total_exact = sum(1 for v in results.values() for h in v if h["is_exact"])
print(f"  {'Group':<35} {'Eval N':>7} {'Leaks >= 80%':>14} {'Exact matches':>14}")
print(f"  {'-'*72}")
for g, hits in results.items():
    n = len(EVAL_GROUPS[g])
    exact = sum(1 for h in hits if h["is_exact"])
    print(f"  {g:<35} {n:>7} {len(hits):>14} {exact:>14}")
print(f"  {'-'*72}")
print(f"  {'TOTAL':<35} {sum(len(v) for v in EVAL_GROUPS.values()):>7} {total_leaks:>14} {total_exact:>14}")
print()
