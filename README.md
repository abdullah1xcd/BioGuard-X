# BioGuard X — Hierarchical Multimodal Biometric Security Platform

BioGuard X is a full-stack multimodal biometric security application combining Face, Voice, and Fingerprint recognition with adaptive policy fusion, multi-tenant Firestore RBAC, server-side AES-256-GCM encrypted template storage, and Vercel serverless/Express compatibility.

## Architecture Overview

- **Frontend (Vite ES Modules + CSS)**:
  - **Face Engine** (`src/js/faceEngine.js`): Uses `@vladmandic/human` (BlazeFace + FaceRes 1024-D embeddings + FaceMesh + anti-spoof / liveness nets), pose/lighting/blur checks, and 4-frame motion/blink/head-yaw liveness capture.
  - **Voice Engine** (`src/shared/voiceDsp.ts`): Extracts 96-D CMVN MFCC + Delta + F0 pitch embeddings in 16 kHz PCM, plus dynamic range, SNR, and clipping replay heuristics.
  - **Fingerprint Engine** (`src/shared/fingerprintEngine.ts`): Performs illumination normalization, directional Gabor enhancement, segmentation, thinning/minutiae extraction, and affine/RANSAC ridge-minutiae matching returning explicit `MATCH`, `NO MATCH`, or `INCONCLUSIVE`.
- **Shared Verification Core (`src/shared/`)**:
  - `fusionEngine.ts`: Supports `face_only`, `voice_only`, `fingerprint_only`, `face_voice`, `face_fingerprint`, `voice_fingerprint`, `three_modal`, and `hierarchical` pipelines under `weighted_score`, `strict_and`, or `hierarchical_adaptive` policies with strict input range checking, custom `modalityWeights`, conflict guard, separated `identityConfidence` / `sampleQualityScore` / `livenessConfidence`, and optional `strictLiveness`.
  - `metrics.ts`: Separates Operational logs, Synthetic QA probes, and Labeled Benchmark trials. Computes Wilson 95% confidence intervals, EER/AUC, `inconclusiveRate`, `livenessFailureRate`, and `sampleQualityDistribution`. Displays `Insufficient validated data` when fewer than 3 genuine and 3 impostor labeled trials exist.
- **Backend API (`server.ts`)**:
  - Express API (running on port `3000` locally and bundled as an Express framework target on Vercel).
  - Enforces Firebase ID token verification (`requireAuth`), Firestore-backed RBAC (`requireCapability`), per-user UID data isolation, AES-256-GCM (`v2` per-record random salt + `scrypt`) biometric vault encryption with key rotation (`/api/v1/vault/rotate`), single-use HMAC liveness challenge tokens (`/api/v1/liveness/challenge`), `Idempotency-Key` anti-replay protection, strict CORS checks, and optional server-side Gemini AI Security Analyst integration.

## Security & Biometric Limitations (Honest Scope)

- **Liveness / Anti-Spoofing**:
  - Live camera captures run multi-frame motion and neural anti-spoof heuristics plus optional challenge cues (blink / head turn).
  - Static image uploads never falsely report `LIVENESS PASSED`; they return `INCONCLUSIVE` (with pass-through texture screening only).
  - Browser microphone capture evaluates acoustic replay heuristics cleanly, while spoken passphrase speech-to-text (ASR) verification is **not** implemented in browser mode (reported honestly as `INCONCLUSIVE`).
  - Fingerprint image uploads have **no** hardware capacitive/ultrasonic PAD sensor in the browser (`NOT SUPPORTED`; `trustedSensorAttestation: false`).
- **Benchmarking**:
  - No public external biometric dataset (LFW, VoxCeleb, FVC) is bundled or executed in this repository. Classification accuracy cards require labeled evaluation records and report `Insufficient validated data` below threshold.

## Environment Variables

Copy `.env.example` and configure these variables in `.env` (local) or Vercel Project Settings:

| Variable | Required | Purpose |
| --- | --- | --- |
| `BIOGUARD_VAULT_SECRET` | Yes (for vault ops) | 32+ character secret for AES-256-GCM vault v2 encryption and HMAC challenge signing |
| `BIOGUARD_VAULT_SECRET_PREVIOUS` | No | Previous 32+ character vault secret during key rotation |
| `GEMINI_API_KEY` | Optional | Enables `/api/v1/ai/analyze` and `/api/v1/ai/report` |
| `UPSTASH_REDIS_REST_URL` | Optional | Distributed rate limiting & cross-instance anti-replay nonce storage |
| `UPSTASH_REDIS_REST_TOKEN` | Optional | Bearer token for Upstash Redis REST API |
| `ALLOWED_ORIGINS` | Optional | Comma-separated extra allowed CORS origins in production |

## Local Development, Testing & Verification

```bash
npm ci
npm run typecheck
npm run lint
npm run test
npm run build
```

Deploy Firestore security rules from `firestore.rules` before sharing in production and verify RBAC & per-user UID isolation in your Firebase project.
