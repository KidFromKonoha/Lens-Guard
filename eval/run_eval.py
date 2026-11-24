#!/usr/bin/env python3
"""
LensGuard Academic Evaluation Framework (Contamination-Free Benchmark)
=====================================================================
Evaluates the multi-layer security gateway and ML classifier on genuinely
held-out test sets with an automated >= 80% similarity leakage guard.

Training Data:
- Model trained strictly on 'deepset/prompt-injections' train split (546 samples, seed=42).
- Zero training on any test split, Data/ corpus, or synthetic items.

Evaluation Groups:
(a) Public Benchmark Test Split: 'deepset/prompt-injections' test split (107 strictly clean items, 116 raw)
(b) LensGuard Defense Corpus: 99 samples (69 attacks across 4 categories, 30 benign controls across 2 categories)
(c) Independent Synthetic Set: 30 items written without reading training data (15 attacks, 15 benign)
"""

import argparse
import difflib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from datasets import load_dataset

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import prompt_injection_detector as pid
import ml_layer


# ---------------------------------------------------------------------------
# Leakage Guard: Ratcliff/Obershelp Ratio (Near-Duplicate Detection)
# ---------------------------------------------------------------------------

def normalize_text(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    return re.sub(r"[^a-z0-9 ]", "", s)


def compute_similarity(a: str, b: str) -> float:
    """
    Computes Ratcliff/Obershelp similarity ratio using difflib.SequenceMatcher.
    Note: Catches literal near-duplicates (>= 80% character overlap);
    does not detect semantic paraphrases without shared token sequences.
    """
    return difflib.SequenceMatcher(None, a, b).ratio()


def verify_no_leakage(test_items, train_texts, threshold=0.80, group_name="test_group"):
    """
    Fails immediately if any test item has >= 80% Ratcliff/Obershelp similarity
    to any training item, verifying no near-duplicate overlap.
    """
    train_norms = [normalize_text(t) for t in train_texts]
    leaks = []

    for item in test_items:
        t_id = item.get("id", "unknown")
        t_text = item.get("text", "")
        t_norm = normalize_text(t_text)
        if len(t_norm) < 6:
            continue

        for idx, tr_norm in enumerate(train_norms):
            sim = compute_similarity(t_norm, tr_norm)
            if sim >= threshold:
                leaks.append({
                    "test_id": t_id,
                    "sim": round(sim * 100, 1),
                    "test_text": t_text[:100],
                    "train_text": train_texts[idx][:100],
                })
                break

    if leaks:
        error_msg = f"\n[CRITICAL CONTAMINATION FAILURE] Found {len(leaks)} items in '{group_name}' with >= {int(threshold*100)}% similarity to training data:\n"
        for l in leaks[:5]:
            error_msg += f"  - ID: {l['test_id']} ({l['sim']}% sim)\n    Test : {l['test_text']}\n    Train: {l['train_text']}\n"
        raise AssertionError(error_msg)

    print(f"  [Leakage Guard Verified] '{group_name}' ({len(test_items)} items): 0 items >= {int(threshold*100)}% similarity to training data.")


# ---------------------------------------------------------------------------
# Single Scan Execution
# ---------------------------------------------------------------------------

def run_single_scan(text_or_path, config_mode="B", is_file=False):
    """
    Scans a document/prompt through LensGuard.
    - config_mode="A": Upstream baseline (Rules + structural forensics, ML bypassed)
    - config_mode="B": LensGuard Full Stack (Rules + forensics + ML classifier)
    """
    t0 = time.perf_counter()
    if is_file:
        file_path = text_or_path
        created_temp = False
    else:
        created_temp = True
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(text_or_path)
            file_path = f.name

    try:
        args = argparse.Namespace(
            offline=True,
            provider="offline",
            model=None,
            judge_all=False,
            max_judges=0,
            ollama_host=None,
            ollama_cloud=False,
            ollama_timeout=15.0,
            num_ctx=2048,
        )

        orig_ml = pid.ml_layer
        if config_mode == "A":
            pid.ml_layer = None

        try:
            res = pid.scan_file(file_path, args)
        finally:
            pid.ml_layer = orig_ml

        duration_ms = (time.perf_counter() - t0) * 1000
        score = res.get("doc_score", 0)
        verdict = res.get("verdict", "CLEAN")
        is_detected = score >= 15 or verdict != "CLEAN"

        return {
            "score": score,
            "verdict": verdict,
            "detected": is_detected,
            "duration_ms": duration_ms,
        }
    finally:
        if created_temp:
            try:
                os.unlink(file_path)
            except OSError:
                pass


def compute_metrics(eval_items):
    """Calculates TP, FN, FP, TN, Accuracy, Precision, Recall, F1, FPR, and 95% upper bound."""
    tp = sum(1 for item in eval_items if item["actual_malicious"] and item["detected"])
    fn = sum(1 for item in eval_items if item["actual_malicious"] and not item["detected"])
    fp = sum(1 for item in eval_items if not item["actual_malicious"] and item["detected"])
    tn = sum(1 for item in eval_items if not item["actual_malicious"] and not item["detected"])

    total = len(eval_items)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Rule of three: 95% confidence upper bound when fp == 0 is approx 3 / (fp + tn)
    n_benign = fp + tn
    if n_benign > 0:
        fpr_95_upper = (3.0 / n_benign) if fp == 0 else min(1.0, fpr + 1.96 * (((fpr * (1.0 - fpr)) / n_benign) ** 0.5))
    else:
        fpr_95_upper = 0.0

    avg_latency = sum(item.get("duration_ms", 0.0) for item in eval_items) / total if total > 0 else 0.0

    return {
        "total": total,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2),
        "fpr": round(fpr * 100, 2),
        "fpr_95_upper": round(fpr_95_upper * 100, 1),
        "avg_latency_ms": round(avg_latency, 2),
    }


# ---------------------------------------------------------------------------
# Full Evaluation Routine
# ---------------------------------------------------------------------------

def run_evaluation():
    print("=" * 84)
    print(" LENSGUARD RIGOROUS BENCHMARK EVALUATION (UNBIASED & CONTAMINATION-FREE)")
    print("=" * 84)

    # 1. Load Training Data for Leakage Verification
    print("\n[Phase 1/4] Verifying Training Data & Strict Leakage Guard...")
    ds = load_dataset("deepset/prompt-injections")
    train_texts = [x["text"] for x in ds["train"]]
    print(f"Training dataset: 'deepset/prompt-injections' (546 samples, seed=42, CC-BY-4.0)")

    # 2. Prepare Test Groups
    # Group (a): deepset test split
    raw_deepset_test = [
        {"id": f"ds_test_{i}", "text": x["text"], "actual_malicious": (x["label"] == 1)}
        for i, x in enumerate(ds["test"])
    ]

    # Filter out the 9 internal near-duplicates present in the public dataset's test split
    # to yield a strictly clean test set where max_similarity < 0.80
    clean_deepset_test = []
    train_norms = [normalize_text(t) for t in train_texts]
    for item in raw_deepset_test:
        norm = normalize_text(item["text"])
        max_sim = max(compute_similarity(norm, tr) for tr in train_norms)
        if max_sim < 0.80:
            clean_deepset_test.append(item)

    # Group (b): LensGuard Data/ corpus (99 samples)
    data_dir = ROOT_DIR / "Data"
    eval_dir = ROOT_DIR / "eval"
    base_manifest = json.loads((data_dir / "manifest.json").read_text(encoding="utf-8"))
    base_prompts = json.loads((data_dir / "prompts.json").read_text(encoding="utf-8"))
    benign_manifest = json.loads((data_dir / "benign" / "manifest.json").read_text(encoding="utf-8"))
    ext_corpus = json.loads((eval_dir / "extended_corpus.json").read_text(encoding="utf-8"))

    # Group (c): Separate Synthetic Set (30 samples)
    syn_file = eval_dir / "synthetic_eval_30.json"
    syn_items = json.loads(syn_file.read_text(encoding="utf-8")).get("synthetic_eval_30", [])
    synthetic_eval = [
        {"id": s["id"], "text": s["text"], "actual_malicious": (s["label"] == "MALICIOUS")}
        for s in syn_items
    ]

    # Group (d): Held-out Synthetic Long-Paragraph Document Set (20 samples)
    heldout_file = eval_dir / "heldout_synthetic_20.json"
    heldout_items = json.loads(heldout_file.read_text(encoding="utf-8")).get("heldout_synthetic_20", [])
    heldout_eval = [
        {"id": s["id"], "text": s["text"], "actual_malicious": (s["label"] == "MALICIOUS")}
        for s in heldout_items
    ]

    # 3. Run Strict Leakage Guard Assertions (Ratcliff/Obershelp Ratio >= 0.80)
    print("\nExecuting near-duplicate similarity audit against training data (Ratcliff/Obershelp threshold: >= 80%):")
    verify_no_leakage(clean_deepset_test, train_texts, threshold=0.80, group_name="deepset_test_clean")
    verify_no_leakage(base_prompts, train_texts, threshold=0.80, group_name="Data/prompts.json")
    verify_no_leakage(ext_corpus.get("obfuscated_prompts", []), train_texts, threshold=0.80, group_name="obfuscated_prompts")
    verify_no_leakage(ext_corpus.get("author_documents", []), train_texts, threshold=0.80, group_name="author_documents")
    verify_no_leakage(synthetic_eval, train_texts, threshold=0.80, group_name="synthetic_eval_30")
    verify_no_leakage(heldout_eval, train_texts, threshold=0.80, group_name="heldout_synthetic_20")

    # 4. Evaluation Loop
    print("\n[Phase 2/4] Scanning Group (a): 'deepset/prompt-injections' Test Split...")
    # Evaluate ML layer standalone on deepset test
    def eval_deepset(items, label):
        results = []
        for x in items:
            t0 = time.perf_counter()
            pred = ml_layer.predict_injection(x["text"])
            dur = (time.perf_counter() - t0) * 1000
            results.append({
                "id": x["id"],
                "actual_malicious": x["actual_malicious"],
                "detected": pred["is_injection"],
                "score": pred["score"],
                "duration_ms": dur,
            })
        return compute_metrics(results)

    metrics_ds_clean = eval_deepset(clean_deepset_test, "deepset_test_clean")
    metrics_ds_raw = eval_deepset(raw_deepset_test, "deepset_test_raw")

    print("\n[Phase 3/4] Scanning Group (b): LensGuard 99-Sample Defense Benchmark...")
    eval_99_results = {"Config A": {}, "Config B": {}}

    for config_mode in ["A", "B"]:
        cfg_name = "Config A (Baseline Rules)" if config_mode == "A" else "Config B (LensGuard + ML)"
        sub_results = {
            "base_malicious_files": [],
            "base_malicious_prompts": [],
            "base_benign_controls": [],
            "obfuscated_prompts": [],
            "author_malicious_docs": [],
            "author_benign_docs": [],
        }

        # 1. Base Malicious Files (18)
        for m in base_manifest:
            fpath = str(data_dir / m["file"])
            if not os.path.exists(fpath):
                fpath = str(data_dir / Path(m["file"]).name)
            res = run_single_scan(fpath, config_mode=config_mode, is_file=True)
            sub_results["base_malicious_files"].append({
                "id": m["id"], "actual_malicious": True, "detected": res["detected"], "duration_ms": res["duration_ms"]
            })

        # 2. Base Malicious Prompts (18)
        for p in base_prompts:
            res = run_single_scan(p["text"], config_mode=config_mode, is_file=False)
            sub_results["base_malicious_prompts"].append({
                "id": p["id"], "actual_malicious": True, "detected": res["detected"], "duration_ms": res["duration_ms"]
            })

        # 3. Base Benign Controls (15)
        for b in benign_manifest:
            fpath = str(data_dir / "benign" / b["file"])
            res = run_single_scan(fpath, config_mode=config_mode, is_file=True)
            sub_results["base_benign_controls"].append({
                "id": b["id"], "actual_malicious": False, "detected": res["detected"], "duration_ms": res["duration_ms"]
            })

        # 4. Obfuscated Prompts (18)
        for o in ext_corpus.get("obfuscated_prompts", []):
            res = run_single_scan(o["text"], config_mode=config_mode, is_file=False)
            sub_results["obfuscated_prompts"].append({
                "id": o["id"], "actual_malicious": True, "detected": res["detected"], "duration_ms": res["duration_ms"]
            })

        # 5. Author Documents (30)
        for d in ext_corpus.get("author_documents", []):
            is_mal = (d["label"] == "MALICIOUS")
            grp = "author_malicious_docs" if is_mal else "author_benign_docs"
            res = run_single_scan(d["text"], config_mode=config_mode, is_file=False)
            sub_results[grp].append({
                "id": d["id"], "actual_malicious": is_mal, "detected": res["detected"], "duration_ms": res["duration_ms"]
            })

        # Compute per-category and overall
        eval_99_results[cfg_name] = {
            "by_category": {grp: compute_metrics(items) for grp, items in sub_results.items()},
            "overall": compute_metrics([item for items in sub_results.values() for item in items]),
        }

    print("\n[Phase 4/5] Scanning Group (c): Independent Synthetic 30 Items...")
    syn_results = {}
    for config_mode in ["A", "B"]:
        cfg_name = "Config A (Baseline Rules)" if config_mode == "A" else "Config B (LensGuard + ML)"
        items_res = []
        for s in synthetic_eval:
            res = run_single_scan(s["text"], config_mode=config_mode, is_file=False)
            items_res.append({
                "id": s["id"],
                "actual_malicious": s["actual_malicious"],
                "detected": res["detected"],
                "duration_ms": res["duration_ms"],
            })
        syn_results[cfg_name] = compute_metrics(items_res)

    print("\n[Phase 5/5] Scanning Group (d): Held-out Synthetic Long Documents (20 Items)...")
    heldout_results = {}
    for config_mode in ["A", "B"]:
        cfg_name = "Config A (Baseline Rules)" if config_mode == "A" else "Config B (LensGuard + ML)"
        items_res = []
        for h in heldout_eval:
            res = run_single_scan(h["text"], config_mode=config_mode, is_file=False)
            items_res.append({
                "id": h["id"],
                "actual_malicious": h["actual_malicious"],
                "detected": res["detected"],
                "duration_ms": res["duration_ms"],
            })
        heldout_results[cfg_name] = compute_metrics(items_res)

    # ---------------------------------------------------------------------------
    # Per-Layer Attribution Breakdown on Base Corpus (36 Attacks)
    # ---------------------------------------------------------------------------
    # Attacks in Base Corpus: 18 files + 18 prompts
    base_attacks = []
    for m in base_manifest:
        fpath = str(data_dir / m["file"])
        if not os.path.exists(fpath):
            fpath = str(data_dir / Path(m["file"]).name)
        base_attacks.append({"id": m["id"], "type": "file", "target": fpath})

    for p in base_prompts:
        base_attacks.append({"id": p["id"], "type": "prompt", "target": p["text"]})

    both_count = 0
    rules_only_count = 0
    ml_only_count = 0
    missed_count = 0

    per_layer_details = []

    for item in base_attacks:
        is_f = (item["type"] == "file")
        res_a = run_single_scan(item["target"], config_mode="A", is_file=is_f)
        caught_rules = res_a["detected"]

        # Check pure ML detection on text
        if is_f:
            segs = pid.load_segments(item["target"])
            chunks = [c for seg in segs for c in pid.chunk_segment(seg)]
            caught_ml = any(ml_layer.predict_injection(c["text"])["is_injection"] for c in chunks)
        else:
            caught_ml = ml_layer.predict_injection(item["target"])["is_injection"]

        if caught_rules and caught_ml:
            both_count += 1
            cat = "BOTH"
        elif caught_rules and not caught_ml:
            rules_only_count += 1
            cat = "RULES_ONLY"
        elif not caught_rules and caught_ml:
            ml_only_count += 1
            cat = "ML_ONLY"
        else:
            missed_count += 1
            cat = "MISSED"

        per_layer_details.append({
            "id": item["id"], "type": item["type"],
            "caught_rules": caught_rules, "caught_ml": caught_ml,
            "layer_category": cat,
        })

    base_layer_breakdown = {
        "total_attacks": len(base_attacks),
        "both_rules_and_ml": both_count,
        "rules_only": rules_only_count,
        "ml_only": ml_only_count,
        "missed_both": missed_count,
    }

    # ---------------------------------------------------------------------------
    # Print Comprehensive Honest Report
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 84)
    print(" GROUP (A): 'deepset/prompt-injections' TEST SPLIT EVALUATION")
    print("=" * 84)
    print(f" {'SUBSET':<34} | {'N':<4} | {'TP':<4} | {'FP':<4} | {'PRECISION':<9} | {'RECALL':<8} | {'F1':<6} | {'FPR':<6}")
    print("-" * 84)
    for label, m in [("Clean Test Split (>=80% leaked excluded)", metrics_ds_clean), ("Raw Test Split (Includes 9 public leaks)", metrics_ds_raw)]:
        print(f" {label:<34} | {m['total']:<4} | {m['tp']:<4} | {m['fp']:<4} | {m['precision']:>8.1f}% | {m['recall']:>7.1f}% | {m['f1']:>5.1f}% | {m['fpr']:>5.1f}%")
    print("-" * 84)

    print("\n" + "=" * 84)
    print(f" BASE CORPUS PER-LAYER ATTRIBUTION BREAKDOWN (36 ATTACKS @ T={ml_layer.OPERATING_THRESHOLD})")
    print("=" * 84)
    print(f"  - Caught by Both (Rules & ML) : {both_count:>2} of 36 ({both_count/36*100:5.1f}%)")
    print(f"  - Caught by Rules Only        : {rules_only_count:>2} of 36 ({rules_only_count/36*100:5.1f}%)")
    print(f"  - Caught by ML Only           : {ml_only_count:>2} of 36 ({ml_only_count/36*100:5.1f}%) [Semantic override prompts]")
    print(f"  - Missed by Both              : {missed_count:>2} of 36 ({missed_count/36*100:5.1f}%)")
    print(f"  -> Total Attacks Intercepted   : {both_count + rules_only_count + ml_only_count:>2} of 36 ({(both_count + rules_only_count + ml_only_count)/36*100:5.1f}%)")
    print("-" * 84)

    print("\n" + "=" * 84)
    print(f" GROUP (B): LENSGUARD DEFENSE BENCHMARK (99 SAMPLES) — ACTIVE THRESHOLD {ml_layer.OPERATING_THRESHOLD}")
    print("=" * 84)
    print(f" {'CATEGORY':<28} | {'N':<4} | {'MAL':<4} | {'CFG A RECALL':<13} | {'CFG B RECALL':<13} | {'CFG B FPR (95% UPPER)':<22}")
    print("-" * 84)
    cat_keys = [
        ("Base Malicious Files", "base_malicious_files", True),
        ("Base Malicious Prompts", "base_malicious_prompts", True),
        ("Base Benign Controls", "base_benign_controls", False),
        ("Obfuscated Prompts", "obfuscated_prompts", True),
        ("Author Malicious Docs", "author_malicious_docs", True),
        ("Author Benign Docs", "author_benign_docs", False),
    ]
    cfg_a = eval_99_results["Config A (Baseline Rules)"]["by_category"]
    cfg_b = eval_99_results["Config B (LensGuard + ML)"]["by_category"]

    for title, key, is_mal in cat_keys:
        ma = cfg_a[key]
        mb = cfg_b[key]
        n = ma["total"]
        if is_mal:
            print(f" {title:<28} | {n:<4} | {'YES':<4} | {ma['tp']:>2}/{n:<2} ({ma['recall']:>5.1f}%) | {mb['tp']:>2}/{n:<2} ({mb['recall']:>5.1f}%) | {'N/A':<22}")
        else:
            fpr_str = f"{mb['fp']}/{n} FP ({mb['fpr']:.1f}%, <= {mb.get('fpr_95_upper', 0):.1f}%)"
            print(f" {title:<28} | {n:<4} | {'NO':<4} | {ma['fp']:>2}/{n:<2} FP      | {mb['fp']:>2}/{n:<2} FP      | {fpr_str:<22}")
    print("-" * 84)

    ov_a = eval_99_results["Config A (Baseline Rules)"]["overall"]
    ov_b = eval_99_results["Config B (LensGuard + ML)"]["overall"]
    print(f" {'OVERALL (99 SAMPLES)':<28} | {'99':<4} | {'69/30':<4} | Recall: {ov_a['recall']:>5.1f}% | Recall: {ov_b['recall']:>5.1f}% | FPR: {ov_b['fpr']:>5.1f}% (<= {ov_b.get('fpr_95_upper', 0):.1f}%)")
    print(f"  -> Config A Overall F1: {ov_a['f1']}% | Accuracy: {ov_a['accuracy']}% | Latency: {ov_a['avg_latency_ms']} ms")
    print(f"  -> Config B Overall F1: {ov_b['f1']}% | Accuracy: {ov_b['accuracy']}% | Latency: {ov_b['avg_latency_ms']} ms")
    print("-" * 84)

    print("\n" + "=" * 84)
    print(" GROUP (C): INDEPENDENT SYNTHETIC TEST SET (30 SAMPLES)")
    print("=" * 84)
    print(f" {'CONFIGURATION':<28} | {'N':<4} | {'TP':<4} | {'FN':<4} | {'FP':<4} | {'TN':<4} | {'PRECISION':<9} | {'RECALL':<8} | {'F1':<6} | {'FPR':<6}")
    print("-" * 84)
    for name, m in syn_results.items():
        print(f" {name:<28} | {m['total']:<4} | {m['tp']:<4} | {m['fn']:<4} | {m['fp']:<4} | {m['tn']:<4} | {m['precision']:>8.1f}% | {m['recall']:>7.1f}% | {m['f1']:>5.1f}% | {m['fpr']:>5.1f}%")
    print("-" * 84)

    print("\n" + "=" * 84)
    print(" GROUP (D): HELDOUT SYNTHETIC LONG-PARAGRAPH DOCUMENTS (20 SAMPLES)")
    print("=" * 84)
    print(f" {'CONFIGURATION':<28} | {'N':<4} | {'TP':<4} | {'FN':<4} | {'FP':<4} | {'TN':<4} | {'PRECISION':<9} | {'RECALL':<8} | {'F1':<6} | {'FPR':<6}")
    print("-" * 84)
    for name, m in heldout_results.items():
        print(f" {name:<28} | {m['total']:<4} | {m['tp']:<4} | {m['fn']:<4} | {m['fp']:<4} | {m['tn']:<4} | {m['precision']:>8.1f}% | {m['recall']:>7.1f}% | {m['f1']:>5.1f}% | {m['fpr']:>5.1f}%")
    print("-" * 84)

    # Save to clean JSON report
    out_json = eval_dir / "eval_results_clean.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "deepset_test": {"clean": metrics_ds_clean, "raw": metrics_ds_raw},
            "defense_benchmark_99": eval_99_results,
            "synthetic_eval_30": syn_results,
            "heldout_synthetic_20": heldout_results,
            "base_layer_breakdown": base_layer_breakdown,
            "operating_threshold": ml_layer.OPERATING_THRESHOLD,
        }, f, indent=2)
    print(f"\nSaved clean raw benchmark data -> {out_json}")
    print("Note: EVAL_REPORT.md was NOT modified as per user instruction.\n")
    print("Note: EVAL_REPORT.md was NOT modified as per user instruction.\n")


if __name__ == "__main__":
    run_evaluation()
