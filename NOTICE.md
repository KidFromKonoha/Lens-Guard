# Notice

LensGuard is an explainable prompt injection security gateway and firewall.

This project is built upon and extends **Prompt Warden** (https://github.com/Soldier224K/Prompt-Injection-Detector), originally created by Soldier224K and released under the MIT License.

### Original Project Attribution:
- Project: Prompt-Injection-Detector (Prompt Warden)
- Author: Soldier224K (https://github.com/Soldier224K)
- License: MIT License (see LICENSE)

### Third-Party Datasets & Resources:
- Dataset: `deepset/prompt-injections` (https://huggingface.co/datasets/deepset/prompt-injections)
- Creator: deepset GmbH
- License: Apache License 2.0 (as listed on the Hugging Face repository; dataset_info also references CC BY 4.0)
- Usage: Training split (546 samples: 343 benign, 203 injection) used for the machine learning classifier layer (`ml_layer.py`).

### LensGuard Additions & Modifications:
- P Mohan Reddy (OUTR Bhubaneswar, B.Tech Final Year Project, Supervised by Dr. Jyotirmayee Routray)
- Machine Learning classification layer (TF-IDF + Logistic Regression) trained on public benchmark data with a single defined operating threshold (0.72)
- Automated near-duplicate check (>= 80% Ratcliff/Obershelp similarity), no overlap found
- Content sanitization and safe untrusted data tagging (`sanitise.py`)
- Dual-path LLM Gateway (`/ask` route: side-by-side comparison with/without LensGuard)
- Character span tracking for visual attack highlighting in the UI
- Extended multi-vector benchmarking and comparative evaluation framework across independent evaluation groups
