# BioGuard X — Intelligent Adaptive Multimodal Biometric Security & Automation Platform

Traditional-ML only (no deep learning). Face (HOG/LBP) + Voice (MFCC/ZCR/RMS) + optional Fingerprint (Gabor+HOG/LBP),
early/score/decision fusion, hierarchical verification, risk engine, Security Analyst Agent, Automation Engine (8 required
workflows + 3 extra), approvals, speech commands with RBAC, challenge-response experiments, SQLite audit trail, 17-page Streamlit app.

## Quick start (Windows)
    py -3.12 -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python -m pytest tests -q
    # put data in datasets/custom/participant_001/{face,voice,commands,fingerprint}/  (see DATASET_GUIDE.md)
    python -m scripts.validate_dataset
    python -m scripts.run_all              # trains + evaluates face/voice/fusion/hierarchy (+fingerprint if present)
    python -m scripts.train_commands       # optional: speech-command model
    python -m scripts.run_security_eval    # agent/automation scenario evaluation
    streamlit run app/main.py

## Fingerprint verification and three-modality workflow
The project now includes a dedicated **Fingerprint Verification** page for claimed-identity checks, plus an optional Face + Voice + Fingerprint path on the Multimodal Verification page. Fingerprint model training is enabled when every participant used in the Face/Voice experiment has at least 10 fingerprint images. After collecting data, run `python -m scripts.run_all`; the bundle must contain `fp_ver`, `refs_fp`, `w3`, and `thr3`. The three-modality route uses validation-calibrated score fusion, while the required Face + Voice early feature fusion remains unchanged. See `FIXES_AND_VALIDATION.md` for changes, test results, and limitations.

## Layout
`src/face, voice, fingerprint, fusion, verification, hierarchy` biometric core · `src/security` risk, policies, permissions, agent ·
`src/automation` engine · `src/commands, challenges, live, llm` · `src/database` SQLite · `app/` Streamlit · `scripts/` · `tests/`.
See BUILD_STATUS.md for the honest implementation status of every feature.
