"""
LensGuard Strict Leakage Checker
Checks for normalized string similarity >= 80% between training data and all evaluation sets.
"""

import json
import re
import difflib
from pathlib import Path
from datasets import load_dataset

ROOT = Path(__file__).resolve().parent.parent

def normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^a-z0-9 ]", "", s)
    return s

def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()

def audit_dataset_leakage():
    print("Loading deepset/prompt-injections train split...")
    ds = load_dataset("deepset/prompt-injections")
    train_texts = [x["text"] for x in ds["train"]]
    train_norms = [normalize(t) for t in train_texts]

    leaks = []

    # 1. Deepset test split
    print(f"Auditing deepset test split ({len(ds['test'])} samples)...")
    for idx, sample in enumerate(ds["test"]):
        text = sample["text"]
        norm = normalize(text)
        for tidx, tr_norm in enumerate(train_norms):
            sim = similarity(norm, tr_norm)
            if sim >= 0.80:
                leaks.append({
                    "group": "deepset_test",
                    "id": f"ds_test_{idx}",
                    "sim": round(sim * 100, 1),
                    "test_text": text[:90],
                    "train_text": train_texts[tidx][:90],
                })

    # 2. Data/prompts.json
    prompts_path = ROOT / "Data" / "prompts.json"
    if prompts_path.exists():
        prompts = json.loads(prompts_path.read_text(encoding="utf-8"))
        print(f"Auditing Data/prompts.json ({len(prompts)} samples)...")
        for p in prompts:
            text = p["text"]
            norm = normalize(text)
            for tidx, tr_norm in enumerate(train_norms):
                sim = similarity(norm, tr_norm)
                if sim >= 0.80:
                    leaks.append({
                        "group": "base_prompts",
                        "id": p["id"],
                        "sim": round(sim * 100, 1),
                        "test_text": text[:90],
                        "train_text": train_texts[tidx][:90],
                    })

    # 3. eval/extended_corpus.json
    ext_path = ROOT / "eval" / "extended_corpus.json"
    if ext_path.exists():
        ext = json.loads(ext_path.read_text(encoding="utf-8"))
        obf = ext.get("obfuscated_prompts", [])
        print(f"Auditing extended_corpus obfuscated_prompts ({len(obf)} samples)...")
        for o in obf:
            text = o["text"]
            norm = normalize(text)
            for tidx, tr_norm in enumerate(train_norms):
                sim = similarity(norm, tr_norm)
                if sim >= 0.80:
                    leaks.append({
                        "group": "obfuscated_prompts",
                        "id": o["id"],
                        "sim": round(sim * 100, 1),
                        "test_text": text[:90],
                        "train_text": train_texts[tidx][:90],
                    })

        author_docs = ext.get("author_documents", [])
        print(f"Auditing extended_corpus author_documents ({len(author_docs)} samples)...")
        for d in author_docs:
            text = d["text"]
            norm = normalize(text)
            for tidx, tr_norm in enumerate(train_norms):
                sim = similarity(norm, tr_norm)
                if sim >= 0.80:
                    leaks.append({
                        "group": "author_documents",
                        "id": d["id"],
                        "sim": round(sim * 100, 1),
                        "test_text": text[:90],
                        "train_text": train_texts[tidx][:90],
                    })

    # 4. eval/synthetic_eval_30.json
    syn_path = ROOT / "eval" / "synthetic_eval_30.json"
    if syn_path.exists():
        syn = json.loads(syn_path.read_text(encoding="utf-8")).get("synthetic_eval_30", [])
        print(f"Auditing synthetic_eval_30 ({len(syn)} samples)...")
        for s in syn:
            text = s["text"]
            norm = normalize(text)
            for tidx, tr_norm in enumerate(train_norms):
                sim = similarity(norm, tr_norm)
                if sim >= 0.80:
                    leaks.append({
                        "group": "synthetic_eval_30",
                        "id": s["id"],
                        "sim": round(sim * 100, 1),
                        "test_text": text[:90],
                        "train_text": train_texts[tidx][:90],
                    })

    print("\n" + "=" * 70)
    print("AUDIT RESULTS (Normalized Similarity >= 80%)")
    print("=" * 70)
    if not leaks:
        print("PERFECT: 0 overlaps found across all evaluation groups!")
    else:
        print(f"Found {len(leaks)} overlaps:")
        for l in leaks:
            print(f"  [{l['sim']}%] Group: {l['group']} | ID: {l['id']}")
            print(f"     Test : {l['test_text']}")
            print(f"     Train: {l['train_text']}")

    return leaks

if __name__ == "__main__":
    audit_dataset_leakage()
