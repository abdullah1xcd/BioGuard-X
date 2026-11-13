// Shared Authoritative Multimodal Fusion & Identity Comparison Engine
// Distinguishes strictly between:
// - Model Similarity Score (calibrated matcher score in [0, 1], NOT identity probability)
// - Verification Confidence (margin + quality + liveness + agreement confidence in [0, 1])
// Supports: face_only, voice_only, fingerprint_only, face_voice, face_fingerprint,
//           voice_fingerprint, three_modal, and hierarchical pipelines.
// Includes quality-weighted fusion, configurable fusion policies, and conflict detection.

import {
  matchFingerprintTemplates,
  type FingerprintTemplate,
} from './fingerprintEngine.ts';

export type ModalityName = 'face' | 'voice' | 'fingerprint';
export type FusionPolicy = 'weighted_score' | 'strict_and' | 'hierarchical_adaptive';

export interface ThresholdConfig {
  face: number;
  voice: number;
  fingerprint: number;
  early: number;
  threeModal: number;
}

export interface ModalityEvaluation {
  modality: ModalityName;
  score: number;
  rawCosine?: number;
  threshold: number;
  qualityScore: number; // 0..100
  passed: boolean;
  strongMismatch: boolean;
  details?: Record<string, unknown>;
}

export interface FusionEvaluationResult {
  pipeline: string;
  fusionPolicy: FusionPolicy;
  modalitiesEvaluated: ModalityName[];
  modalityEvaluations: Record<string, ModalityEvaluation>;
  finalScore: number; // Model similarity score (0..1)
  baseThreshold: number;
  confidence: number; // Verification confidence (0..1)
  confidenceBand: 'high' | 'moderate' | 'low';
  conflictDetected: boolean;
  conflictDetails: string[];
  rejectionReasons: string[];
  outcome: 'match' | 'no_match' | 'not_evaluated';
  reasonCode: string;
  stage?: string;
}

export function rawCosineSimilarity(a: number[], b: number[]): number {
  if (!a?.length || a.length !== b?.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  if (!denom) return 0;
  return Math.max(-1, Math.min(1, dot / denom));
}

export function calibrateSimilarity(rawCos: number, modality: 'face' | 'voice' | 'legacy'): number {
  if (modality === 'face') {
    // FaceRes 1024-D: unrelated < 0.35, genuine > 0.58
    return Number(Math.max(0, Math.min(1, (rawCos - 0.12) / 0.72)).toFixed(4));
  }
  if (modality === 'voice') {
    // Acoustic 96-D CMVN MFCC+Delta+F0: unrelated < 0.42, genuine > 0.65
    return Number(Math.max(0, Math.min(1, (rawCos - 0.15) / 0.72)).toFixed(4));
  }
  // Legacy v1.1 vectors: non-negative cosine clamped cleanly without 0.50 floor inflation
  return Number(Math.max(0, Math.min(1, rawCos)).toFixed(4));
}

export function scoreVectorRefs(
  probe: number[],
  refs: number[][],
  modality: 'face' | 'voice' | 'legacy'
): { score: number; rawCosine: number } {
  if (!refs.length) return { score: 0, rawCosine: 0 };
  let bestRaw = -1;
  let sumRaw = 0;
  let validCount = 0;
  for (const r of refs) {
    if (!Array.isArray(r) || r.length !== probe.length) continue;
    const rc = rawCosineSimilarity(probe, r);
    if (rc > bestRaw) bestRaw = rc;
    sumRaw += rc;
    validCount++;
  }
  if (!validCount) return { score: 0, rawCosine: 0 };
  const blendedRaw = 0.65 * bestRaw + 0.35 * (sumRaw / validCount);
  return {
    score: calibrateSimilarity(blendedRaw, modality),
    rawCosine: Number(blendedRaw.toFixed(4)),
  };
}

export function scoreFingerprintAgainstRefs(
  probe: FingerprintTemplate | number[],
  refs: Array<FingerprintTemplate | number[]>
): { score: number; details: Record<string, unknown> } {
  if (!refs.length) return { score: 0, details: {} };
  if (!Array.isArray(probe)) {
    const structRefs = refs.filter((r): r is FingerprintTemplate => !Array.isArray(r) && Array.isArray(r.minutiae));
    if (structRefs.length > 0) {
      let bestRes = matchFingerprintTemplates(probe, structRefs[0]);
      let sum = 0;
      for (const sr of structRefs) {
        const res = matchFingerprintTemplates(probe, sr);
        sum += res.score;
        if (res.score > bestRes.score) bestRes = res;
      }
      const blended = Number((0.7 * bestRes.score + 0.3 * (sum / structRefs.length)).toFixed(4));
      return {
        score: blended,
        details: {
          matchedMinutiae: bestRes.matchedMinutiae,
          probeMinutiae: bestRes.probeMinutiae,
          refMinutiae: bestRes.refMinutiae,
          estimatedRotationDeg: bestRes.estimatedRotationDeg,
          isPartialMatch: bestRes.isPartialMatch,
          orientationScore: bestRes.orientationScore,
        },
      };
    }
    // Compare descriptor128 if vault only holds legacy 130-D? Wait: 128 != 130 -> incompatible version
    return { score: 0, details: { incompatibleTemplate: true } };
  }

  // Legacy 130-D fallback
  const vecRefs = refs.filter((r): r is number[] => Array.isArray(r) && r.length === probe.length);
  const scored = scoreVectorRefs(probe, vecRefs, 'legacy');
  return { score: scored.score, details: { legacyVector: true, rawCosine: scored.rawCosine } };
}

function getBaseWeight(m: ModalityName): number {
  if (m === 'face') return 0.45;
  if (m === 'voice') return 0.28;
  return 0.27;
}

export function fuseMultimodalScores(params: {
  pipeline: string;
  fusionPolicy?: FusionPolicy;
  thresholds: ThresholdConfig;
  available: Partial<Record<ModalityName, {
    score: number;
    rawCosine?: number;
    qualityScore: number;
    details?: Record<string, unknown>;
  }>>;
  livenessPassed?: boolean;
  livenessScore?: number;
}): FusionEvaluationResult {
  const {
    pipeline,
    fusionPolicy = 'hierarchical_adaptive',
    thresholds,
    available,
    livenessPassed = true,
    livenessScore = 0.88,
  } = params;

  const thrMap: Record<ModalityName, number> = {
    face: thresholds.face ?? 0.72,
    voice: thresholds.voice ?? 0.70,
    fingerprint: thresholds.fingerprint ?? 0.72,
  };

  const evaluateModality = (m: ModalityName): ModalityEvaluation | null => {
    const item = available[m];
    if (!item) return null;
    const thr = thrMap[m];
    const strongMismatch = item.score <= Math.max(0.20, thr - 0.16) || item.score < 0.36;
    return {
      modality: m,
      score: Number(item.score.toFixed(4)),
      rawCosine: item.rawCosine,
      threshold: thr,
      qualityScore: Math.max(0, Math.min(100, Math.round(item.qualityScore))),
      passed: item.score >= thr,
      strongMismatch,
      details: item.details,
    };
  };

  let requested: ModalityName[] = [];
  let baseThreshold = thresholds.face ?? 0.72;
  let stage: string | undefined;

  if (pipeline === 'face' || pipeline === 'face_only') {
    requested = ['face'];
    baseThreshold = thrMap.face;
  } else if (pipeline === 'voice' || pipeline === 'voice_only') {
    requested = ['voice'];
    baseThreshold = thrMap.voice;
  } else if (pipeline === 'fingerprint' || pipeline === 'fingerprint_only') {
    requested = ['fingerprint'];
    baseThreshold = thrMap.fingerprint;
  } else if (pipeline === 'face_voice' || pipeline === 'early_fusion') {
    requested = ['face', 'voice'];
    baseThreshold = Number(((thrMap.face + thrMap.voice) / 2).toFixed(4));
  } else if (pipeline === 'face_fingerprint') {
    requested = ['face', 'fingerprint'];
    baseThreshold = Number(((thrMap.face + thrMap.fingerprint) / 2).toFixed(4));
  } else if (pipeline === 'voice_fingerprint') {
    requested = ['voice', 'fingerprint'];
    baseThreshold = Number(((thrMap.voice + thrMap.fingerprint) / 2).toFixed(4));
  } else if (pipeline === 'three_modal') {
    requested = ['face', 'voice', 'fingerprint'];
    baseThreshold = thresholds.threeModal ?? 0.74;
  } else {
    // hierarchical
    const fEval = evaluateModality('face');
    if (!fEval) {
      return {
        pipeline,
        fusionPolicy,
        modalitiesEvaluated: [],
        modalityEvaluations: {},
        finalScore: 0,
        baseThreshold: thrMap.face,
        confidence: 0,
        confidenceBand: 'low',
        conflictDetected: false,
        conflictDetails: [],
        rejectionReasons: ['Hierarchical verification requires a face probe and enrolled face template.'],
        outcome: 'not_evaluated',
        reasonCode: 'missing_face_modality',
      };
    }
    const highGate = Math.min(0.95, thrMap.face + 0.08);
    const lowGate = Math.max(0.30, thrMap.face - 0.16);
    if (fEval.score >= highGate && !available.voice && !available.fingerprint) {
      requested = ['face'];
      baseThreshold = highGate;
      stage = 'Stage 1 High-Confidence Face Accept';
    } else if (fEval.score <= lowGate && !available.voice && !available.fingerprint) {
      requested = ['face'];
      baseThreshold = lowGate;
      stage = 'Stage 1 Strong Face Reject';
    } else {
      requested = ['face'];
      if (available.voice) requested.push('voice');
      if (available.fingerprint) requested.push('fingerprint');
      if (requested.length === 1) {
        // Uncertain band with no secondary modality available
        return {
          pipeline: 'hierarchical',
          fusionPolicy,
          modalitiesEvaluated: ['face'],
          modalityEvaluations: { face: fEval },
          finalScore: fEval.score,
          baseThreshold: thrMap.face,
          confidence: 0.35,
          confidenceBand: 'low',
          conflictDetected: false,
          conflictDetails: [],
          rejectionReasons: [
            `Face similarity (${(fEval.score * 100).toFixed(1)}%) landed in the uncertain band (${(lowGate * 100).toFixed(0)}%–${(highGate * 100).toFixed(0)}%); secondary Voice or Fingerprint probe required.`,
          ],
          outcome: 'not_evaluated',
          reasonCode: 'hierarchical_uncertain_secondary_required',
          stage: 'Uncertain band — secondary factor required',
        };
      }
      baseThreshold = requested.length === 3 ? (thresholds.threeModal ?? 0.74) : Number(((thrMap.face + (available.voice ? thrMap.voice : thrMap.fingerprint)) / 2).toFixed(4));
      stage = `Stage 2 Escalated Multimodal Fusion (${requested.join(' + ')})`;
    }
  }

  const evals: ModalityEvaluation[] = [];
  const evalMap: Record<string, ModalityEvaluation> = {};
  const missing: ModalityName[] = [];

  for (const m of requested) {
    const ev = evaluateModality(m);
    if (!ev) missing.push(m);
    else {
      evals.push(ev);
      evalMap[m] = ev;
    }
  }

  if (missing.length > 0 || evals.length === 0) {
    return {
      pipeline,
      fusionPolicy,
      modalitiesEvaluated: evals.map((e) => e.modality),
      modalityEvaluations: evalMap,
      finalScore: 0,
      baseThreshold,
      confidence: 0,
      confidenceBand: 'low',
      conflictDetected: false,
      conflictDetails: [],
      rejectionReasons: [`Missing required modality sample or enrolled template: ${missing.join(', ')}`],
      outcome: 'not_evaluated',
      reasonCode: 'missing_template_or_sample',
      stage,
    };
  }

  // Quality-weighted fusion (only justified by modality reliability & signal quality)
  let weightSum = 0;
  let weightedScoreSum = 0;
  for (const ev of evals) {
    const qFactor = 0.5 + 0.5 * (ev.qualityScore / 100);
    const w = getBaseWeight(ev.modality) * qFactor;
    weightSum += w;
    weightedScoreSum += w * ev.score;
  }
  const finalScore = Number((weightSum > 0 ? weightedScoreSum / weightSum : 0).toFixed(4));

  // Conflict Detection:
  // Prevent a weak/passing modality from overriding strong mismatch evidence on another modality
  const conflictDetails: string[] = [];
  const rejectionReasons: string[] = [];
  const passing = evals.filter((e) => e.passed);
  const failing = evals.filter((e) => !e.passed);
  const strongMismatches = evals.filter((e) => e.strongMismatch);
  const scores = evals.map((e) => e.score);
  const spread = scores.length >= 2 ? Math.max(...scores) - Math.min(...scores) : 0;

  let conflictDetected = false;
  if (evals.length >= 2 && strongMismatches.length > 0 && passing.length > 0) {
    conflictDetected = true;
    for (const sm of strongMismatches) {
      conflictDetails.push(
        `Strong mismatch in ${sm.modality} (${(sm.score * 100).toFixed(1)}% vs threshold ${(sm.threshold * 100).toFixed(0)}%) conflicts with passing ${passing.map((p) => p.modality).join(', ')}.`
      );
    }
  } else if (evals.length >= 2 && spread >= 0.36 && failing.length > 0) {
    conflictDetected = true;
    conflictDetails.push(
      `High cross-modality divergence (${(spread * 100).toFixed(1)} pp spread across ${evals.map((e) => e.modality).join(', ')}).`
    );
  }

  // Determine outcome according to fusionPolicy + conflict guard + liveness
  let outcome: 'match' | 'no_match' = 'no_match';
  let reasonCode = `${pipeline}_match`;

  if (!livenessPassed) {
    outcome = 'no_match';
    reasonCode = 'spoof_or_liveness_failed';
    rejectionReasons.push('Liveness / anti-spoofing check failed.');
  } else if (conflictDetected) {
    outcome = 'no_match';
    reasonCode = 'conflicting_biometric_evidence';
    rejectionReasons.push(...conflictDetails);
  } else if (fusionPolicy === 'strict_and') {
    if (failing.length === 0 && finalScore >= baseThreshold) {
      outcome = 'match';
      reasonCode = `${pipeline}_strict_match`;
    } else {
      outcome = 'no_match';
      reasonCode = 'strict_policy_modality_failed';
      for (const f of failing) {
        rejectionReasons.push(`${f.modality} similarity (${(f.score * 100).toFixed(1)}%) fell below ${(f.threshold * 100).toFixed(0)}% threshold.`);
      }
      if (finalScore < baseThreshold) {
        rejectionReasons.push(`Fused similarity (${(finalScore * 100).toFixed(1)}%) fell below ${(baseThreshold * 100).toFixed(0)}% policy threshold.`);
      }
    }
  } else {
    // weighted_score or hierarchical_adaptive: still disallow match if strong mismatch exists even without passing peers
    if (strongMismatches.length > 0) {
      outcome = 'no_match';
      reasonCode = `${strongMismatches[0].modality}_strong_mismatch`;
      for (const sm of strongMismatches) {
        rejectionReasons.push(`${sm.modality} showed strong mismatch (${(sm.score * 100).toFixed(1)}%).`);
      }
    } else if (finalScore >= baseThreshold) {
      outcome = 'match';
      reasonCode = stage?.includes('Stage 1') ? 'hierarchical_stage1_face_match' : `${pipeline}_match`;
    } else {
      outcome = 'no_match';
      reasonCode = `${pipeline}_below_threshold`;
      rejectionReasons.push(`Fused similarity (${(finalScore * 100).toFixed(1)}%) fell below ${(baseThreshold * 100).toFixed(0)}% threshold.`);
      for (const f of failing) {
        rejectionReasons.push(`${f.modality} scored ${(f.score * 100).toFixed(1)}% (threshold ${(f.threshold * 100).toFixed(0)}%).`);
      }
    }
  }

  // Calibrated Verification Confidence (NOT raw cosine similarity!)
  const margin = Math.abs(finalScore - baseThreshold);
  const marginFactor = Math.min(1, margin / 0.22); // 0 at exact boundary, 1 at >=22pp margin
  const meanQuality = evals.reduce((s, e) => s + e.qualityScore, 0) / evals.length / 100;
  const agreementFactor = conflictDetected ? 0.25 : evals.length >= 2 && failing.length === 0 ? 1.0 : 0.78;
  const rawConf = (0.45 * marginFactor + 0.30 * meanQuality + 0.15 * livenessScore + 0.10 * agreementFactor);
  const confidence = Number(Math.max(0.05, Math.min(0.99, conflictDetected ? rawConf * 0.65 : rawConf)).toFixed(3));
  const confidenceBand: 'high' | 'moderate' | 'low' =
    confidence >= 0.75 ? 'high' : confidence >= 0.48 ? 'moderate' : 'low';

  return {
    pipeline,
    fusionPolicy,
    modalitiesEvaluated: evals.map((e) => e.modality),
    modalityEvaluations: evalMap,
    finalScore,
    baseThreshold,
    confidence,
    confidenceBand,
    conflictDetected,
    conflictDetails,
    rejectionReasons,
    outcome,
    reasonCode,
    stage,
  };
}
