import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

process.env.BIOGUARD_SKIP_LISTEN = '1';

import { extractVoiceFeaturesV2 } from '../src/shared/voiceDsp.ts';
import {
  FP_SIZE,
  classifyFingerprintDecision,
  extractFingerprintTemplateFromGray128,
  matchFingerprintTemplates,
} from '../src/shared/fingerprintEngine.ts';
import {
  fuseMultimodalScores,
  rawCosineSimilarity,
  scoreVectorRefs,
} from '../src/shared/fusionEngine.ts';
import {
  buildBiometricAnalyticsReport,
  computeClassificationMetrics,
  wilsonCI95,
} from '../src/shared/metrics.ts';
import {
  isAuthorizedDevAdmin,
  isDevTestingModeActive,
  recommendPipelineForModalities,
} from '../src/js/config.js';

const FEATURE_VERSION = 'v2.0-multimodal';

function synthesizeSpeakerPcm(params: {
  sampleRate: number;
  durationSec: number;
  f0Hz: number;
  formantBias: number;
  amplitude?: number;
  noiseLevel?: number;
  clippingBoost?: number;
  seed?: number;
}): Float32Array {
  const {
    sampleRate,
    durationSec,
    f0Hz,
    formantBias,
    amplitude = 0.35,
    noiseLevel = 0.005,
    clippingBoost = 1,
    seed = 42,
  } = params;
  const total = Math.floor(sampleRate * durationSec);
  const out = new Float32Array(total);
  let state = seed >>> 0;
  const nextRand = () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return (state / 0xffffffff) * 2 - 1;
  };

  for (let i = 0; i < total; i++) {
    const t = i / sampleRate;
    // Two voiced bursts separated by brief pause so VAD & segments activate naturally
    const inPause = t > 0.72 && t < 0.88;
    const env = inPause ? 0.02 : 0.7 + 0.3 * Math.sin(2 * Math.PI * 3.1 * t);
    // Natural vibrato so pitch is realistic (not synthetic flat tone)
    const f0Inst = f0Hz * (1 + 0.018 * Math.sin(2 * Math.PI * 5.2 * t));
    const phase = 2 * Math.PI * f0Inst * t;
    // Vocal tract harmonic shaping (F1/F2 emphasis unique to speaker)
    const wave =
      0.55 * Math.sin(phase) +
      (0.32 + formantBias * 0.25) * Math.sin(2 * phase + 0.3) +
      (0.28 - formantBias * 0.14) * Math.sin(3 * phase + 0.8) +
      (0.22 + formantBias * 0.22) * Math.sin(5 * phase + 1.1) +
      0.14 * Math.sin(7 * phase + 0.4) +
      0.08 * Math.sin(11 * phase);
    const val = (wave * amplitude * env + nextRand() * noiseLevel) * clippingBoost;
    out[i] = Math.max(-1, Math.min(1, val));
  }
  return out;
}

function synthesizeFingerprintGray128(options: {
  seed: number;
  rotationDeg?: number;
  shiftX?: number;
  shiftY?: number;
  cropFraction?: number;
  ridgeFreqFactor?: number;
}): Float32Array {
  const {
    seed,
    rotationDeg = 0,
    shiftX = 0,
    shiftY = 0,
    cropFraction = 1,
    ridgeFreqFactor = 1,
  } = options;
  const N = FP_SIZE;
  const out = new Float32Array(N * N);
  const rad = (rotationDeg * Math.PI) / 180;
  const cosR = Math.cos(rad);
  const sinR = Math.sin(rad);
  const cx = N / 2;
  const cy = N / 2;

  // Deterministic dislocation cores inside the ridge pattern to yield rich endings & bifurcations
  const cores =
    seed === 1
      ? [
          { x: -16, y: -14, polarity: 1 },
          { x: 18, y: -10, polarity: -1 },
          { x: -10, y: 16, polarity: 1 },
          { x: 14, y: 18, polarity: -1 },
          { x: 0, y: -2, polarity: 1 },
        ]
      : [
          { x: -20, y: 12, polarity: -1 },
          { x: 16, y: 8, polarity: 1 },
          { x: -6, y: -18, polarity: -1 },
          { x: 22, y: -16, polarity: 1 },
          { x: 4, y: 20, polarity: -1 },
        ];

  const ovalR = 46;
  const freq = (2 * Math.PI) / (7.5 * ridgeFreqFactor);

  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      // Partial print crop simulation (blank out right/bottom side when cropFraction < 1)
      if (cropFraction < 1 && x > N * cropFraction) {
        out[y * N + x] = 235;
        continue;
      }

      // Inverse rigid transform to reference fingerprint coordinates
      const dx = x - cx - shiftX;
      const dy = y - cy - shiftY;
      const rx = dx * cosR + dy * sinR;
      const ry = -dx * sinR + dy * cosR;

      const ellip = (rx * rx) / (ovalR * ovalR * 0.85) + (ry * ry) / (ovalR * ovalR * 1.15);
      if (ellip > 1) {
        out[y * N + x] = 232;
        continue;
      }

      // Loop/whorl phase carrier + topological dislocations (create natural ridge endings & bifurcations)
      let phase =
        seed === 1
          ? freq * (ry + 0.16 * rx + 11 * Math.sin(rx / 24))
          : freq * (rx * 0.88 - 0.35 * ry + 13 * Math.cos(ry / 20));
      for (const c of cores) {
        phase += c.polarity * Math.atan2(ry - c.y, rx - c.x);
      }

      // Dark ridges (low intensity) vs bright valleys (high intensity)
      const ridgeVal = 128 + 86 * Math.cos(phase);
      out[y * N + x] = Math.max(10, Math.min(245, ridgeVal));
    }
  }
  return out;
}

test('Voice DSP: resampling invariance (48kHz vs 16kHz), noise robustness, clipping spoof detection, and short-buffer guard', () => {
  const speakerA48k = synthesizeSpeakerPcm({
    sampleRate: 48000,
    durationSec: 1.6,
    f0Hz: 118,
    formantBias: 0.75,
    seed: 101,
  });
  const speakerA16k = synthesizeSpeakerPcm({
    sampleRate: 16000,
    durationSec: 1.6,
    f0Hz: 118,
    formantBias: 0.75,
    seed: 102,
  });
  const speakerANoisy = synthesizeSpeakerPcm({
    sampleRate: 16000,
    durationSec: 1.6,
    f0Hz: 118,
    formantBias: 0.75,
    noiseLevel: 0.018,
    seed: 103,
  });
  const speakerB = synthesizeSpeakerPcm({
    sampleRate: 16000,
    durationSec: 1.6,
    f0Hz: 225,
    formantBias: -0.7,
    seed: 202,
  });

  const featA48 = extractVoiceFeaturesV2(speakerA48k, 48000, 'mic');
  const featA16 = extractVoiceFeaturesV2(speakerA16k, 16000, 'mic');
  const featANoisy = extractVoiceFeaturesV2(speakerANoisy, 16000, 'mic');
  const featB = extractVoiceFeaturesV2(speakerB, 16000, 'mic');

  assert.equal(featA48.dim, 96);
  assert.equal(featA48.featureVersion, FEATURE_VERSION);

  const genuine48vs16 = rawCosineSimilarity(featA48.vector, featA16.vector);
  const genuineNoisy = rawCosineSimilarity(featA16.vector, featANoisy.vector);
  const impostorAvsB = rawCosineSimilarity(featA16.vector, featB.vector);

  assert.ok(genuine48vs16 > 0.92, `Expected 48kHz vs 16kHz same-speaker cosine > 0.92, got ${genuine48vs16}`);
  assert.ok(genuineNoisy > 0.80, `Expected noisy same-speaker cosine > 0.80, got ${genuineNoisy}`);
  assert.ok(
    genuine48vs16 - impostorAvsB > 0.35,
    `Expected strong genuine/impostor separation, got genuine=${genuine48vs16}, impostor=${impostorAvsB}`
  );

  // Heavy clipping replay trigger (>12% clipped)
  const clippedReplay = synthesizeSpeakerPcm({
    sampleRate: 16000,
    durationSec: 1.4,
    f0Hz: 120,
    formantBias: 0.6,
    clippingBoost: 5.5,
    seed: 303,
  });
  const featClipped = extractVoiceFeaturesV2(clippedReplay, 16000, 'mic');
  assert.ok(featClipped.stats.clippingRatio > 0.12, `Expected clippingRatio > 0.12, got ${featClipped.stats.clippingRatio}`);
  assert.ok(
    featClipped.stats.spoofSignals.some((s) => s.toLowerCase().includes('replay') || s.toLowerCase().includes('clipping')),
    `Expected replay/clipping spoof signal, got ${JSON.stringify(featClipped.stats.spoofSignals)}`
  );

  // Short buffer must throw
  assert.throws(() => extractVoiceFeaturesV2(new Float32Array(200), 16000, 'mic'), /too short/i);
});

test('Fingerprint Engine: rejects blank images, supports rotation/translation/partial matching, and separates distinct subjects', () => {
  const refA = extractFingerprintTemplateFromGray128(synthesizeFingerprintGray128({ seed: 1 }));
  const rotA = extractFingerprintTemplateFromGray128(synthesizeFingerprintGray128({ seed: 1, rotationDeg: 18 }));
  const shiftA = extractFingerprintTemplateFromGray128(synthesizeFingerprintGray128({ seed: 1, shiftX: 5, shiftY: -4 }));
  const partialA = extractFingerprintTemplateFromGray128(synthesizeFingerprintGray128({ seed: 1, cropFraction: 0.62 }));
  const impB = extractFingerprintTemplateFromGray128(synthesizeFingerprintGray128({ seed: 2, ridgeFreqFactor: 1.12 }));

  // Flat uniform blank canvas should be invalid
  const blank = new Float32Array(FP_SIZE * FP_SIZE).fill(210);
  const blankTpl = extractFingerprintTemplateFromGray128(blank);
  assert.equal(blankTpl.validPrint, false);
  assert.equal(blankTpl.minutiae.length, 0);

  assert.equal(refA.validPrint, true, `Expected refA validPrint=true (minutiae=${refA.minutiae.length}, coh=${refA.meanCoherence}, density=${refA.ridgeDensity})`);
  assert.ok(refA.minutiae.length >= 6, `Expected >=6 extracted minutiae, got ${refA.minutiae.length}`);

  const selfRes = matchFingerprintTemplates(refA, refA);
  const rotRes = matchFingerprintTemplates(rotA, refA);
  const shiftRes = matchFingerprintTemplates(shiftA, refA);
  const partialRes = matchFingerprintTemplates(partialA, refA);
  const impRes = matchFingerprintTemplates(impB, refA);

  assert.ok(selfRes.score >= 0.90, `Expected self match >= 0.90, got ${selfRes.score}`);
  assert.ok(rotRes.score >= 0.65, `Expected +18 deg rotated genuine match >= 0.65, got ${rotRes.score}`);
  assert.ok(shiftRes.score >= 0.70, `Expected translated genuine match >= 0.70, got ${shiftRes.score}`);
  assert.ok(partialRes.score >= 0.55, `Expected partial print genuine match >= 0.55, got ${partialRes.score}`);
  assert.ok(
    rotRes.score > impRes.score + 0.12 && shiftRes.score > impRes.score + 0.15,
    `Expected rotated/shifted genuine scores (${rotRes.score}, ${shiftRes.score}) well above impostor (${impRes.score})`
  );

  // Quality labels, templateStatus, and explicit 3-state classifyFingerprintDecision (MATCH | NO MATCH | INCONCLUSIVE)
  assert.equal(refA.qualityLabel, 'Good Quality');
  assert.equal(refA.templateStatus, 'Valid Minutiae Template');
  assert.equal(blankTpl.qualityLabel, 'Insufficient Ridge Details');
  assert.equal(blankTpl.templateStatus, 'Insufficient Features');

  assert.equal(classifyFingerprintDecision(selfRes, 0.72, refA.qualityScore, true).decision, 'MATCH');
  assert.equal(classifyFingerprintDecision(impRes, 0.72, impB.qualityScore, true).decision, 'NO MATCH');
  assert.equal(
    classifyFingerprintDecision({ ...selfRes, score: 0.73, matchedMinutiae: 2 }, 0.72, 70, true).decision,
    'INCONCLUSIVE'
  );
  assert.equal(
    classifyFingerprintDecision({ ...selfRes, score: 0.73 }, 0.72, 52, true).decision,
    'INCONCLUSIVE'
  );
  assert.equal(classifyFingerprintDecision(selfRes, 0.72, 30, false).decision, 'INCONCLUSIVE');
});

test('Multimodal Fusion Engine: enforces all 7 pipelines, conflict guard, strict_and policy, hierarchical escalation & calibrated confidence', () => {
  const thresholds = { face: 0.72, voice: 0.70, fingerprint: 0.72, early: 0.72, threeModal: 0.74 };

  // 1. All 7 explicit pipelines evaluate expected modalities
  const allPipelines = [
    { name: 'face_only', expected: ['face'] },
    { name: 'voice_only', expected: ['voice'] },
    { name: 'fingerprint_only', expected: ['fingerprint'] },
    { name: 'face_voice', expected: ['face', 'voice'] },
    { name: 'face_fingerprint', expected: ['face', 'fingerprint'] },
    { name: 'voice_fingerprint', expected: ['voice', 'fingerprint'] },
    { name: 'three_modal', expected: ['face', 'voice', 'fingerprint'] },
  ];
  for (const p of allPipelines) {
    const res = fuseMultimodalScores({
      pipeline: p.name,
      fusionPolicy: 'weighted_score',
      thresholds,
      available: {
        face: { score: 0.88, qualityScore: 90 },
        voice: { score: 0.85, qualityScore: 86 },
        fingerprint: { score: 0.86, qualityScore: 88 },
      },
      livenessPassed: true,
      livenessScore: 0.92,
    });
    assert.deepEqual(res.modalitiesEvaluated, p.expected);
    assert.equal(res.outcome, 'match');
    assert.equal(res.conflictDetected, false);
  }

  // 2. Conflict guard: strong mismatch (0.22) must NOT be overridden by passing modality (0.90)
  const conflictRes = fuseMultimodalScores({
    pipeline: 'face_voice',
    fusionPolicy: 'weighted_score',
    thresholds,
    available: {
      face: { score: 0.90, qualityScore: 95 },
      voice: { score: 0.22, qualityScore: 85 },
    },
    livenessPassed: true,
    livenessScore: 0.90,
  });
  assert.equal(conflictRes.conflictDetected, true);
  assert.equal(conflictRes.outcome, 'no_match');
  assert.equal(conflictRes.reasonCode, 'conflicting_biometric_evidence');
  assert.ok(conflictRes.rejectionReasons.length >= 1);

  // 3. strict_and rejects even when weighted average passes threshold
  const strictRes = fuseMultimodalScores({
    pipeline: 'face_voice',
    fusionPolicy: 'strict_and',
    thresholds,
    available: {
      face: { score: 0.86, qualityScore: 95 },
      voice: { score: 0.61, qualityScore: 85 }, // below 0.70, not strongMismatch (<0.54)
    },
    livenessPassed: true,
    livenessScore: 0.90,
  });
  assert.ok(strictRes.finalScore > 0.73, 'Weighted average exceeded threshold');
  assert.equal(strictRes.outcome, 'no_match', 'strict_and must reject when voice < threshold');
  assert.equal(strictRes.reasonCode, 'strict_policy_modality_failed');

  // 4. Hierarchical escalation when face is in uncertain band
  const hierEscalationRequired = fuseMultimodalScores({
    pipeline: 'hierarchical',
    fusionPolicy: 'hierarchical_adaptive',
    thresholds,
    available: { face: { score: 0.70, qualityScore: 85 } },
  });
  assert.equal(hierEscalationRequired.outcome, 'not_evaluated');
  assert.equal(hierEscalationRequired.reasonCode, 'hierarchical_uncertain_secondary_required');

  // 5. Confidence is calibrated distinctly from similarity score (lower near boundary)
  const boundaryMatch = fuseMultimodalScores({
    pipeline: 'face_only',
    thresholds,
    available: { face: { score: 0.725, qualityScore: 80 } },
    livenessPassed: true,
    livenessScore: 0.85,
  });
  const strongMatch = fuseMultimodalScores({
    pipeline: 'face_only',
    thresholds,
    available: { face: { score: 0.95, qualityScore: 95 } },
    livenessPassed: true,
    livenessScore: 0.95,
  });
  assert.notEqual(boundaryMatch.confidence, boundaryMatch.finalScore);
  assert.ok(strongMatch.confidence > boundaryMatch.confidence + 0.25);

  // 6. Explicit 3-outcome finalDecision (VERIFIED | REJECTED | INCONCLUSIVE) & 4-state liveness gating
  assert.equal(strongMatch.finalDecision, 'VERIFIED');
  assert.equal(strongMatch.livenessStatus, 'LIVENESS PASSED');
  assert.equal(strictRes.finalDecision, 'REJECTED');

  const livenessFailRes = fuseMultimodalScores({
    pipeline: 'face_only',
    thresholds,
    available: { face: { score: 0.94, qualityScore: 95 } },
    livenessPassed: false,
    livenessStatus: 'LIVENESS FAILED',
    livenessScore: 0.18,
  });
  assert.equal(livenessFailRes.finalDecision, 'REJECTED');
  assert.equal(livenessFailRes.livenessStatus, 'LIVENESS FAILED');
  assert.equal(livenessFailRes.reasonCode, 'spoof_or_liveness_failed');

  // Static upload yields INCONCLUSIVE livenessStatus yet allows VERIFIED if identity evidence passes without spoof trigger
  const staticFaceRes = fuseMultimodalScores({
    pipeline: 'face_only',
    thresholds,
    available: { face: { score: 0.91, qualityScore: 90 } },
    livenessPassed: true,
    livenessStatus: 'INCONCLUSIVE',
    livenessScore: 0.5,
  });
  assert.equal(staticFaceRes.livenessStatus, 'INCONCLUSIVE');
  assert.equal(staticFaceRes.finalDecision, 'VERIFIED');

  // Fingerprint INCONCLUSIVE must prevent false VERIFIED approval
  const fpIncRes = fuseMultimodalScores({
    pipeline: 'face_fingerprint',
    fusionPolicy: 'weighted_score',
    thresholds,
    available: {
      face: { score: 0.93, qualityScore: 92 },
      fingerprint: { score: 0.73, qualityScore: 50, inconclusive: true, decision: 'INCONCLUSIVE' },
    },
    livenessPassed: true,
    livenessStatus: 'LIVENESS PASSED',
  });
  assert.equal(fpIncRes.finalDecision, 'INCONCLUSIVE');
  assert.equal(fpIncRes.modalityEvaluations.fingerprint.status, 'INCONCLUSIVE');
});

test('Metrics & Subject-Disjoint Evaluation: exact confusion formulas, Wilson CI, EER/AUC, unlabeled exclusion & zero identity leakage', () => {
  const trials = [
    { score: 0.92, genuine: true },
    { score: 0.84, genuine: true },
    { score: 0.76, genuine: true },
    { score: 0.61, genuine: true }, // FN at 0.72
    { score: 0.28, genuine: false },
    { score: 0.41, genuine: false },
    { score: 0.55, genuine: false },
    { score: 0.79, genuine: false }, // FP at 0.72
  ];
  const m = computeClassificationMetrics(trials, 0.72);
  assert.equal(m.tp, 3);
  assert.equal(m.fn, 1);
  assert.equal(m.tn, 3);
  assert.equal(m.fp, 1);
  assert.equal(m.insufficientData, false);
  assert.equal(m.accuracy, 0.75);
  assert.equal(m.tar, 0.75);
  assert.equal(m.far, 0.25);
  assert.equal(m.frr, 0.25);
  assert.equal(m.precision, 0.75);
  assert.equal(m.recall, 0.75);
  assert.equal(m.f1, 0.75);
  assert.ok(m.auc > 0.80);

  const ci = wilsonCI95(3, 4);
  assert.ok(ci.low > 0.25 && ci.high < 0.99 && ci.low < 0.75 && ci.high > 0.75);

  // Unlabeled operational records must NEVER count toward classification accuracy
  const report = buildBiometricAnalyticsReport(
    [
      { outcome: 'match', score: 0.95, groundTruth: 'unlabeled', livenessPassed: true, processingTimeMs: 42 },
      { outcome: 'match', score: 0.91, groundTruth: 'unlabeled', livenessPassed: true, processingTimeMs: 38 },
      { outcome: 'no_match', score: 0.30, groundTruth: 'unlabeled', livenessPassed: false, processingTimeMs: 55 },
      { outcome: 'match', score: 0.88, groundTruth: 'genuine', isTestProbe: true, processingTimeMs: 40 },
    ],
    4,
    4
  );
  assert.equal(report.totalAttempts, 4);
  assert.equal(report.labeledAttempts, 1);
  assert.equal(report.unlabeledAttempts, 3);
  assert.equal(report.classification.insufficientData, true, 'Must flag insufficientData when <3 genuine or <3 impostor');
  assert.equal(report.classification.sampleCount, 1);
  assert.equal(report.operationalVerificationSuccessRate, 0.6667);
  assert.equal(report.livenessSuccessRate, 0.6667);
  assert.equal(report.latency.measuredCount, 4);

  // Subject-disjoint evaluation test (subjects 1..4 vs non-overlapping subject probes, zero identity leakage)
  const galleryIds = ['subj_01', 'subj_02', 'subj_03'];
  const testIds = ['subj_04', 'subj_05', 'subj_06'];
  assert.equal(galleryIds.filter((id) => testIds.includes(id)).length, 0);

  const gallery = new Map<string, number[][]>();
  galleryIds.forEach((id, idx) => {
    const enroll = extractVoiceFeaturesV2(
      synthesizeSpeakerPcm({ sampleRate: 16000, durationSec: 1.5, f0Hz: 110 + idx * 45, formantBias: (idx - 1) * 0.6, seed: 500 + idx }),
      16000,
      'mic'
    ).vector;
    gallery.set(id, [enroll]);
  });

  const disjointTrials = [];
  // Genuine probes from held-out capture session + disjoint impostor probes from held-out subjects
  for (let idx = 0; idx < galleryIds.length; idx++) {
    const gProbe = extractVoiceFeaturesV2(
      synthesizeSpeakerPcm({ sampleRate: 48000, durationSec: 1.5, f0Hz: 110 + idx * 45, formantBias: (idx - 1) * 0.6, noiseLevel: 0.012, seed: 600 + idx }),
      48000,
      'mic'
    ).vector;
    disjointTrials.push({
      score: scoreVectorRefs(gProbe, gallery.get(galleryIds[idx])!, 'voice').score,
      genuine: true,
    });

    const impProbe = extractVoiceFeaturesV2(
      synthesizeSpeakerPcm({ sampleRate: 16000, durationSec: 1.5, f0Hz: 265 + idx * 25, formantBias: -0.85, seed: 700 + idx }),
      16000,
      'mic'
    ).vector;
    disjointTrials.push({
      score: scoreVectorRefs(impProbe, gallery.get(galleryIds[idx])!, 'voice').score,
      genuine: false,
    });
  }
  const disjointMetrics = computeClassificationMetrics(disjointTrials, 0.70);
  assert.equal(disjointMetrics.insufficientData, false);
  assert.ok(disjointMetrics.accuracy >= 0.83, `Expected subject-disjoint voice accuracy >= 0.83, got ${disjointMetrics.accuracy}`);

  // Strict 3-dataset isolation + capture failure tracking
  const mixedReport = buildBiometricAnalyticsReport(
    [
      { outcome: 'match', finalDecision: 'VERIFIED', score: 0.91, groundTruth: 'unlabeled', datasetCategory: 'operational', livenessStatus: 'LIVENESS PASSED', processingTimeMs: 44 },
      { outcome: 'not_evaluated', finalDecision: 'INCONCLUSIVE', reasonCode: 'fingerprint_inconclusive', captureFailure: true, groundTruth: 'unlabeled', datasetCategory: 'operational', livenessStatus: 'NOT SUPPORTED', processingTimeMs: 21 },
      { outcome: 'match', finalDecision: 'VERIFIED', score: 0.93, groundTruth: 'genuine', datasetCategory: 'synthetic_qa', isTestProbe: true, livenessStatus: 'LIVENESS PASSED', processingTimeMs: 31 },
      { outcome: 'no_match', finalDecision: 'REJECTED', score: 0.29, groundTruth: 'impostor', datasetCategory: 'synthetic_qa', isTestProbe: true, livenessStatus: 'LIVENESS FAILED', processingTimeMs: 28 },
    ],
    2,
    2
  );
  assert.equal(mixedReport.datasets.operational.totalAttempts, 2);
  assert.equal(mixedReport.datasets.operational.verifiedCount, 1);
  assert.equal(mixedReport.datasets.operational.inconclusiveCount, 1);
  assert.equal(mixedReport.datasets.operational.captureFailureCount, 1);
  assert.equal(mixedReport.datasets.operational.captureFailureRate, 0.5);
  assert.equal(mixedReport.datasets.syntheticQa.totalProbes, 2);
  assert.equal(mixedReport.datasets.benchmark.totalLabeledTrials, 2);
  assert.equal(mixedReport.datasets.benchmark.operationalLabeledTrials, 0);
  assert.equal(mixedReport.datasets.benchmark.insufficientData, true);
  assert.equal(mixedReport.datasets.benchmark.insufficientDataMessage, 'Insufficient validated data');
});

test('Server Vault AES-256-GCM v2 secret enforcement, key rotation, health diagnostics & HTTP auth checks', async () => {
  process.env.BIOGUARD_SKIP_LISTEN = '1';
  const prevSecret = process.env.BIOGUARD_VAULT_SECRET;
  const prevPrevSecret = process.env.BIOGUARD_VAULT_SECRET_PREVIOUS;
  const serverMod = await import('../server.ts');
  const {
    VaultSecretError,
    decryptVaultMap,
    decryptVaultMapWithMeta,
    encryptVaultMap,
    default: app,
  } = serverMod;
  assert.equal(serverMod.FEATURE_VERSION, FEATURE_VERSION);

  const sampleVault = {
    ID_TEST_01: {
      identityRef: 'ID_TEST_01',
      featureVersion: FEATURE_VERSION,
      enrolledAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      modalities: { face: [[0.1, 0.2, 0.3]] },
    },
  };

  try {
    // 1. Fail-closed when BIOGUARD_VAULT_SECRET is unset or too short
    delete process.env.BIOGUARD_VAULT_SECRET;
    delete process.env.BIOGUARD_VAULT_SECRET_PREVIOUS;
    assert.throws(() => encryptVaultMap(sampleVault), VaultSecretError);
    process.env.BIOGUARD_VAULT_SECRET = 'too-short-secret';
    assert.throws(() => encryptVaultMap(sampleVault), VaultSecretError);

    // 2. HTTP /api/v1/health stays HTTP 200 with vault_ready=false when secret is unconfigured
    const unconfServer = http.createServer(app);
    await new Promise<void>((resolve) => unconfServer.listen(0, '127.0.0.1', resolve));
    const unconfAddr = unconfServer.address() as AddressInfo;
    try {
      const hRes = await fetch(`http://127.0.0.1:${unconfAddr.port}/api/v1/health`);
      assert.equal(hRes.status, 200);
      const hJson = (await hRes.json()) as { vault_ready: boolean; vault_mode: string };
      assert.equal(hJson.vault_ready, false);
      assert.equal(hJson.vault_mode, 'not_configured');
    } finally {
      await new Promise<void>((resolve, reject) => unconfServer.close((err) => (err ? reject(err) : resolve())));
    }

    // 3. Configure strong 32+ char vault secret -> v2 per-record random salt + scrypt AES-256-GCM
    const oldSecret = 'old-test-vault-secret-minimum-32-characters-0001';
    const newSecret = 'new-rotated-vault-secret-minimum-32-chars-0002';
    process.env.BIOGUARD_VAULT_SECRET = oldSecret;

    const enc1 = encryptVaultMap(sampleVault);
    const enc2 = encryptVaultMap(sampleVault);
    const parsed1 = JSON.parse(enc1) as { v: number; kdf: string; alg: string; salt: string; ciphertext: string };
    const parsed2 = JSON.parse(enc2) as { salt: string; ciphertext: string };
    assert.equal(parsed1.v, 2);
    assert.equal(parsed1.kdf, 'scrypt');
    assert.equal(parsed1.alg, 'aes-256-gcm');
    assert.notEqual(parsed1.salt, parsed2.salt);
    assert.notEqual(parsed1.ciphertext, parsed2.ciphertext);
    assert.deepEqual(decryptVaultMap(enc1), sampleVault);

    // 4. Key rotation: previous secret -> primary secret re-encryption
    process.env.BIOGUARD_VAULT_SECRET = newSecret;
    process.env.BIOGUARD_VAULT_SECRET_PREVIOUS = oldSecret;
    const meta = decryptVaultMapWithMeta(enc1);
    assert.equal(meta.rotatedFromPrevious, true);
    assert.equal(meta.needsRotation, true);
    assert.deepEqual(meta.map, sampleVault);

    const rotatedPayload = encryptVaultMap(meta.map);
    delete process.env.BIOGUARD_VAULT_SECRET_PREVIOUS;
    const rotatedMeta = decryptVaultMapWithMeta(rotatedPayload);
    assert.equal(rotatedMeta.rotatedFromPrevious, false);
    assert.equal(rotatedMeta.needsRotation, false);
    assert.deepEqual(rotatedMeta.map, sampleVault);

    // 5. HTTP health (configured) + strict 401 auth enforcement on protected endpoints
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    try {
      const healthRes = await fetch(`${baseUrl}/api/v1/health`);
      assert.equal(healthRes.status, 200);
      const health = (await healthRes.json()) as {
        status: string;
        feature_version: string;
        vault_ready: boolean;
        vault_mode: string;
      };
      assert.equal(health.status, 'ok');
      assert.equal(health.feature_version, FEATURE_VERSION);
      assert.equal(health.vault_ready, true);
      assert.equal(health.vault_mode, 'env_secret_v2');

      const protectedGets = ['/api/v1/auth/me', '/api/v1/diagnostics'];
      for (const ep of protectedGets) {
        const r = await fetch(`${baseUrl}${ep}`);
        assert.equal(r.status, 401, `Expected 401 on unauthenticated GET ${ep}, got ${r.status}`);
      }

      const protectedPosts = [
        '/api/v1/identities/enroll',
        '/api/v1/verification/multimodal',
        '/api/v1/identities/compare',
        '/api/v1/identities/identify',
        '/api/v1/vault/rotate',
      ];
      for (const ep of protectedPosts) {
        const r = await fetch(`${baseUrl}${ep}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        assert.equal(r.status, 401, `Expected 401 on unauthenticated POST ${ep}, got ${r.status}`);
      }
    } finally {
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    }
  } finally {
    if (prevSecret === undefined) delete process.env.BIOGUARD_VAULT_SECRET;
    else process.env.BIOGUARD_VAULT_SECRET = prevSecret;
    if (prevPrevSecret === undefined) delete process.env.BIOGUARD_VAULT_SECRET_PREVIOUS;
    else process.env.BIOGUARD_VAULT_SECRET_PREVIOUS = prevPrevSecret;
  }
});

test('Developer/Testing Mode is strictly isolated to authorized admins and defaults to off', () => {
  // Non-admin roles must never enter Developer/Testing Mode even if state flag is forced true
  for (const role of ['viewer', 'operator', 'security_analyst']) {
    const injectedState = {
      profile: { role },
      permissions: role === 'viewer' ? ['view_identities', 'view_analytics'] : ['perform_verification', 'create_identity'],
      devTestingMode: true,
    };
    assert.equal(isAuthorizedDevAdmin(injectedState), false, `Role ${role} must not be authorized as dev admin`);
    assert.equal(isDevTestingModeActive(injectedState), false, `Role ${role} must never activate dev testing mode`);
  }

  // Authorized admins default to false and activate only when toggled true
  for (const adminRole of ['administrator', 'super_admin']) {
    const defaultAdminState = {
      profile: { role: adminRole },
      permissions: ['manage_roles', 'change_settings'],
      devTestingMode: false,
    };
    assert.equal(isAuthorizedDevAdmin(defaultAdminState), true, `Role ${adminRole} should be authorized dev admin`);
    assert.equal(isDevTestingModeActive(defaultAdminState), false, `Role ${adminRole} should default dev mode to false`);

    const enabledAdminState = { ...defaultAdminState, devTestingMode: true };
    assert.equal(isDevTestingModeActive(enabledAdminState), true, `Role ${adminRole} should activate dev mode when enabled`);
  }

  // Permission-based check if manage_roles is present
  assert.equal(
    isDevTestingModeActive({ profile: { role: 'custom_admin' }, permissions: ['manage_roles'], devTestingMode: true }),
    true
  );

  // Empty/unauthenticated state
  assert.equal(isAuthorizedDevAdmin(null), false);
  assert.equal(isDevTestingModeActive({}), false);

  // Pipeline recommendation mapping for enrollment/verification UX
  assert.equal(recommendPipelineForModalities(['face']), 'face_only');
  assert.equal(recommendPipelineForModalities(['voice']), 'voice_only');
  assert.equal(recommendPipelineForModalities(['fingerprint']), 'fingerprint_only');
  assert.equal(recommendPipelineForModalities(['face', 'voice']), 'hierarchical');
  assert.equal(recommendPipelineForModalities(['face', 'fingerprint']), 'face_fingerprint');
  assert.equal(recommendPipelineForModalities(['voice', 'fingerprint']), 'voice_fingerprint');
  assert.equal(recommendPipelineForModalities(['face', 'voice', 'fingerprint']), 'three_modal');
});

test('Fusion Engine hardening: validates inputs, fails closed when omitted/strict liveness, supports custom modalityWeights & separated confidences', () => {
  const thresholds = { face: 0.72, voice: 0.70, fingerprint: 0.72, early: 0.72, threeModal: 0.74 };

  // 1. Out-of-range / NaN inputs throw explicit errors instead of silently saturating
  assert.throws(
    () =>
      fuseMultimodalScores({
        pipeline: 'face_only',
        thresholds,
        available: { face: { score: Number.NaN, qualityScore: 80 } },
        livenessPassed: true,
      }),
    /Invalid biometric parameter/i
  );
  assert.throws(
    () =>
      fuseMultimodalScores({
        pipeline: 'face_only',
        thresholds,
        available: { face: { score: 1.25, qualityScore: 80 } },
        livenessPassed: true,
      }),
    /Invalid biometric parameter/i
  );
  assert.throws(
    () =>
      fuseMultimodalScores({
        pipeline: 'face_only',
        thresholds,
        available: { face: { score: 0.85, qualityScore: 140 } },
        livenessPassed: true,
      }),
    /Invalid biometric parameter/i
  );
  assert.throws(
    () =>
      fuseMultimodalScores({
        pipeline: 'face_only',
        thresholds,
        modalityWeights: { face: 0 },
        available: { face: { score: 0.85, qualityScore: 85 } },
        livenessPassed: true,
      }),
    /Invalid biometric parameter/i
  );

  // 2. Omitted liveness NEVER silently upgrades to LIVENESS PASSED
  const omittedLiv = fuseMultimodalScores({
    pipeline: 'face_only',
    thresholds,
    available: { face: { score: 0.88, qualityScore: 90 } },
  });
  assert.equal(omittedLiv.livenessStatus, 'INCONCLUSIVE');
  assert.equal(omittedLiv.livenessDecision, 'INCONCLUSIVE');
  assert.equal(omittedLiv.finalDecision, 'VERIFIED');

  // 3. strictLiveness policy blocks INCONCLUSIVE liveness from verifying
  const strictBlocked = fuseMultimodalScores({
    pipeline: 'face_only',
    thresholds,
    livenessPolicy: { strictLiveness: true },
    livenessStatus: 'INCONCLUSIVE',
    available: { face: { score: 0.92, qualityScore: 92 } },
  });
  assert.equal(strictBlocked.finalDecision, 'INCONCLUSIVE');
  assert.equal(strictBlocked.outcome, 'not_evaluated');
  assert.equal(strictBlocked.reasonCode, 'liveness_inconclusive_blocked');

  // 4. Custom modalityWeights normalize cleanly and shift fused score deterministically
  const voiceHeavy = fuseMultimodalScores({
    pipeline: 'face_voice',
    fusionPolicy: 'weighted_score',
    thresholds,
    modalityWeights: { face: 0.2, voice: 0.8 },
    available: {
      face: { score: 0.90, qualityScore: 90 },
      voice: { score: 0.72, qualityScore: 90 },
    },
    livenessPassed: true,
    livenessScore: 0.90,
  });
  const faceHeavy = fuseMultimodalScores({
    pipeline: 'face_voice',
    fusionPolicy: 'weighted_score',
    thresholds,
    modalityWeights: { face: 0.8, voice: 0.2 },
    available: {
      face: { score: 0.90, qualityScore: 90 },
      voice: { score: 0.72, qualityScore: 90 },
    },
    livenessPassed: true,
    livenessScore: 0.90,
  });
  assert.ok(faceHeavy.finalScore > voiceHeavy.finalScore + 0.08);

  // 5. Separated confidence metrics (identityConfidence, sampleQualityScore, livenessConfidence)
  assert.ok(faceHeavy.identityConfidence > 0 && faceHeavy.identityConfidence <= 0.99);
  assert.equal(faceHeavy.sampleQualityScore, 0.9);
  assert.equal(faceHeavy.livenessConfidence, 0.9);
  assert.equal(strictBlocked.livenessConfidence, 0.5);
});

test('Analytics report tracks inconclusiveRate, livenessFailureRate, livenessBreakdown, and sampleQualityDistribution', () => {
  const report = buildBiometricAnalyticsReport(
    [
      {
        outcome: 'match',
        finalDecision: 'VERIFIED',
        score: 0.9,
        faceQuality: 86,
        livenessStatus: 'LIVENESS PASSED',
        groundTruth: 'unlabeled',
      },
      {
        outcome: 'not_evaluated',
        finalDecision: 'INCONCLUSIVE',
        score: 0.55,
        faceQuality: 48,
        livenessStatus: 'INCONCLUSIVE',
        groundTruth: 'unlabeled',
      },
      {
        outcome: 'no_match',
        finalDecision: 'REJECTED',
        score: 0.35,
        faceQuality: 22,
        livenessStatus: 'LIVENESS FAILED',
        groundTruth: 'unlabeled',
      },
      {
        outcome: 'match',
        finalDecision: 'VERIFIED',
        score: 0.88,
        faceQuality: 80,
        livenessStatus: 'NOT SUPPORTED',
        datasetCategory: 'synthetic_qa',
        isTestProbe: true,
        groundTruth: 'genuine',
      },
    ],
    2,
    2
  );

  assert.equal(report.inconclusiveRate, 0.25);
  assert.equal(report.livenessKnownCount, 2);
  assert.equal(report.livenessFailureRate, 0.5);
  assert.deepEqual(report.livenessBreakdown, {
    passed: 1,
    failed: 1,
    inconclusive: 1,
    notSupported: 1,
  });
  assert.equal(report.datasets.operational.livenessNotSupportedCount, 0);
  assert.equal(report.sampleQualityDistribution.measuredCount, 4);
  assert.equal(report.sampleQualityDistribution.goodCount, 2);
  assert.equal(report.sampleQualityDistribution.borderlineCount, 1);
  assert.equal(report.sampleQualityDistribution.poorCount, 1);
  assert.equal(report.datasets.benchmark.insufficientDataMessage, 'Insufficient validated data');
});

test('Server challenge tokens, anti-replay nonces, strict CORS guard & security headers', async () => {
  process.env.BIOGUARD_SKIP_LISTEN = '1';
  const serverMod = await import('../server.ts');
  const {
    isOriginAllowed,
    createChallengeToken,
    verifyChallengeToken,
    consumeReplayNonceLocal,
    app,
  } = serverMod;

  // 1. Origin / CORS validation
  assert.equal(isOriginAllowed('https://bioguard.example', 'bioguard.example'), true);
  assert.equal(isOriginAllowed('https://evil.example', 'bioguard.example'), false);
  assert.equal(isOriginAllowed('not-a-url', 'bioguard.example'), false);

  // 2. Single-use challenge tokens: valid -> verified -> replay rejected; tampered / wrong uid rejected
  const secret = 'test-challenge-secret-minimum-32-characters-long';
  const issued = createChallengeToken({ uid: 'user_123', ttlMs: 30_000, secretOverride: secret });
  assert.ok(['blink', 'turn_left', 'turn_right'].includes(issued.faceChallenge));
  assert.equal(issued.voicePassphrase.split(' ').length, 3);

  const tampered = `${issued.challengeToken.slice(0, -4)}AAAA`;
  const tamperedRes = await verifyChallengeToken({ token: tampered, uid: 'user_123', secretOverride: secret });
  assert.equal(tamperedRes.valid, false);
  assert.equal(tamperedRes.reason, 'invalid_challenge_signature');

  const wrongUidRes = await verifyChallengeToken({ token: issued.challengeToken, uid: 'other_user', secretOverride: secret });
  assert.equal(wrongUidRes.valid, false);
  assert.equal(wrongUidRes.reason, 'challenge_subject_mismatch');

  const okRes = await verifyChallengeToken({ token: issued.challengeToken, uid: 'user_123', secretOverride: secret });
  assert.equal(okRes.valid, true);
  assert.equal(okRes.payload?.nonce, issued.nonce);

  const replayRes = await verifyChallengeToken({ token: issued.challengeToken, uid: 'user_123', secretOverride: secret });
  assert.equal(replayRes.valid, false);
  assert.equal(replayRes.reason, 'challenge_replay_detected');

  // 3. Idempotency replay store
  assert.equal(consumeReplayNonceLocal('unit_test', 'nonce_abc', 30_000), true);
  assert.equal(consumeReplayNonceLocal('unit_test', 'nonce_abc', 30_000), false);

  // 4. HTTP headers, strict 403 CORS rejection, and 401 auth on /api/v1/liveness/challenge
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    const hRes = await fetch(`${baseUrl}/api/v1/health`);
    assert.equal(hRes.status, 200);
    assert.equal(hRes.headers.get('cross-origin-opener-policy'), 'same-origin-allow-popups');
    assert.equal(hRes.headers.get('x-content-type-options'), 'nosniff');
    assert.notEqual(hRes.headers.get('x-frame-options'), 'DENY');

    const corsDenied = await fetch(`${baseUrl}/api/v1/health`, {
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(corsDenied.status, 403);
    const corsJson = (await corsDenied.json()) as { error: string };
    assert.equal(corsJson.error, 'cors_origin_denied');

    const challengeUnauth = await fetch(`${baseUrl}/api/v1/liveness/challenge`, { method: 'POST' });
    assert.equal(challengeUnauth.status, 401);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});


