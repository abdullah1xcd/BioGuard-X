// Shared Authoritative Multimodal Fusion & Identity Comparison Engine
// Distinguishes strictly between:
// - Model Similarity Score (calibrated matcher score in [0, 1], NOT identity probability)
// - Verification Confidence (margin + quality + liveness + agreement confidence in [0, 1])
// Supports: face_only, voice_only, fingerprint_only, face_voice, face_fingerprint,
//           voice_fingerprint, three_modal, and hierarchical pipelines.
// Includes quality-weighted fusion, configurable fusion policies, and conflict detection.

import {
  classifyFingerprintDecision,
  matchFingerprintTemplates,
  type FingerprintDecision,
  type FingerprintTemplate,
} from './fingerprintEngine.ts';

export type ModalityName = 'face' | 'voice' | 'fingerprint';
export type FusionPolicy = 'weighted_score' | 'strict_and' | 'hierarchical_adaptive';
export type ModalityStatus = 'MATCH' | 'NO MATCH' | 'INCONCLUSIVE' | 'NOT EVALUATED';
export type FinalDecision = 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';
export type LivenessStatus = 'LIVENESS PASSED' | 'LIVENESS FAILED' | 'INCONCLUSIVE' | 'NOT SUPPORTED';
export type LivenessDecision = 'PASSED' | 'FAILED' | 'INCONCLUSIVE';

export interface ThresholdConfig {
  face: number;
  voice: number;
  fingerprint: number;
  early: number;
  threeModal: number;
}

export interface ModalityWeightConfig {
  face?: number;
  voice?: number;
  fingerprint?: number;
}

export interface LivenessPolicy {
  strictLiveness?: boolean;
  requiredModalities?: ModalityName[];
}

export interface ModalityEvaluation {
  modality: ModalityName;
  score: number;
  rawCosine?: number;
  threshold: number;
  qualityScore: number; // 0..100
  passed: boolean;
  inconclusive?: boolean;
  status: ModalityStatus;
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
  confidence: number; // Overall verification confidence (0..1)
  identityConfidence: number; // Match margin + cross-modality agreement (0..1)
  sampleQualityScore: number; // Normalized capture quality across evaluated modalities (0..1)
  livenessConfidence: number; // Liveness evidence integrity confidence (0..1)
  confidenceBand: 'high' | 'moderate' | 'low';
  conflictDetected: boolean;
  conflictDetails: string[];
  rejectionReasons: string[];
  outcome: 'match' | 'no_match' | 'not_evaluated';
  finalDecision: FinalDecision;
  identityMatch: {
    passed: boolean;
    score: number;
    threshold: number;
    status: ModalityStatus;
  };
  livenessVerification: {
    status: LivenessStatus;
    decision: LivenessDecision;
    score: number;
    confidence: number;
    strictRequired: boolean;
  };
  livenessStatus: LivenessStatus;
  livenessDecision: LivenessDecision;
  fusionExplanation: string;
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
  // Legacy v1.1 vectors: non-negative cosine clamped cleanly
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
  refs: Array<FingerprintTemplate | number[]>,
  threshold = 0.72
): { score: number; decision?: FingerprintDecision; decisionReason?: string; details: Record<string, unknown> } {
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
      const cls = classifyFingerprintDecision(
        { ...bestRes, score: blended },
        threshold,
        probe.qualityScore,
        probe.validPrint
      );
      return {
        score: blended,
        decision: cls.decision,
        decisionReason: cls.reason,
        details: {
          matchedMinutiae: bestRes.matchedMinutiae,
          probeMinutiae: bestRes.probeMinutiae,
          refMinutiae: bestRes.refMinutiae,
          estimatedRotationDeg: bestRes.estimatedRotationDeg,
          isPartialMatch: bestRes.isPartialMatch,
          orientationScore: bestRes.orientationScore,
          decision: cls.decision,
          decisionReason: cls.reason,
          qualityScore: probe.qualityScore,
          qualityLabel: probe.qualityLabel || (probe.validPrint ? 'Good Quality' : 'Poor Quality'),
          templateStatus: probe.templateStatus || (probe.validPrint ? 'Valid Minutiae Template' : 'Insufficient Features'),
          meanCoherence: probe.meanCoherence,
          ridgeDensity: probe.ridgeDensity,
          meanWavelengthPx: probe.meanWavelengthPx,
          validPrint: probe.validPrint,
        },
      };
    }
    return { score: 0, details: { incompatibleTemplate: true } };
  }

  // Legacy 130-D fallback
  const vecRefs = refs.filter((r): r is number[] => Array.isArray(r) && r.length === probe.length);
  const scored = scoreVectorRefs(probe, vecRefs, 'legacy');
  const legacyDecision: FingerprintDecision = scored.score >= threshold ? 'MATCH' : 'NO MATCH';
  return {
    score: scored.score,
    decision: legacyDecision,
    details: { legacyVector: true, rawCosine: scored.rawCosine, decision: legacyDecision },
  };
}

function assertFiniteInRange(name: string, value: unknown, min: number, max: number, exclusiveMin = false): number {
  if (typeof value !== 'number') {
    throw new TypeError(`Invalid biometric parameter "${name}": expected number, got ${typeof value}.`);
  }
  if (!Number.isFinite(value)) {
    throw new RangeError(`Invalid biometric parameter "${name}": value must be finite (received ${String(value)}).`);
  }
  if (exclusiveMin ? value <= min || value > max : value < min || value > max) {
    throw new RangeError(
      `Invalid biometric parameter "${name}": expected ${exclusiveMin ? `(${min}, ${max}]` : `[${min}, ${max}]`}, got ${value}.`
    );
  }
  return value;
}

function getBaseWeight(m: ModalityName, weights?: ModalityWeightConfig): number {
  if (weights && weights[m] !== undefined) {
    return assertFiniteInRange(`modalityWeights.${m}`, weights[m], 0, 1, true);
  }
  if (m === 'face') return 0.45;
  if (m === 'voice') return 0.28;
  return 0.27;
}

export function fuseMultimodalScores(params: {
  pipeline: string;
  fusionPolicy?: FusionPolicy;
  thresholds: ThresholdConfig;
  modalityWeights?: ModalityWeightConfig;
  livenessPolicy?: LivenessPolicy;
  available: Partial<Record<ModalityName, {
    score: number;
    rawCosine?: number;
    qualityScore: number;
    inconclusive?: boolean;
    decision?: FingerprintDecision;
    details?: Record<string, unknown>;
  }>>;
  livenessPassed?: boolean;
  livenessStatus?: LivenessStatus;
  livenessScore?: number;
}): FusionEvaluationResult {
  const {
    pipeline,
    fusionPolicy = 'hierarchical_adaptive',
    thresholds,
    modalityWeights,
    livenessPolicy,
    available,
    livenessPassed,
    livenessStatus: rawLivenessStatus,
    livenessScore: rawLivenessScore,
  } = params;

  if (!thresholds || typeof thresholds !== 'object') {
    throw new TypeError('thresholds object is required.');
  }

  // Validate modalityWeights if supplied
  if (modalityWeights !== undefined) {
    if (!modalityWeights || typeof modalityWeights !== 'object') {
      throw new TypeError('modalityWeights must be an object when provided.');
    }
    const weightKeys: ModalityName[] = ['face', 'voice', 'fingerprint'];
    let specifiedCount = 0;
    let specifiedSum = 0;
    for (const k of weightKeys) {
      if (modalityWeights[k] !== undefined) {
        specifiedSum += assertFiniteInRange(`modalityWeights.${k}`, modalityWeights[k], 0, 1, true);
        specifiedCount++;
      }
    }
    if (specifiedCount > 0 && specifiedSum <= 0) {
      throw new RangeError('modalityWeights sum must be strictly positive.');
    }
  }

  // Resolve 4-state liveness status and 3-state liveness decision (omitted liveness MUST NOT silently pass)
  let livenessStatus: LivenessStatus;
  if (rawLivenessStatus !== undefined) {
    livenessStatus = rawLivenessStatus;
  } else if (livenessPassed === true) {
    livenessStatus = 'LIVENESS PASSED';
  } else if (livenessPassed === false) {
    livenessStatus = 'LIVENESS FAILED';
  } else {
    livenessStatus = 'INCONCLUSIVE';
  }

  const livenessDecision: LivenessDecision =
    livenessStatus === 'LIVENESS FAILED' || livenessPassed === false
      ? 'FAILED'
      : livenessStatus === 'LIVENESS PASSED'
      ? 'PASSED'
      : 'INCONCLUSIVE';

  const defaultLivScore = livenessDecision === 'PASSED' ? 0.88 : livenessDecision === 'FAILED' ? 0.15 : 0.5;
  const livenessScore = assertFiniteInRange(
    'livenessScore',
    rawLivenessScore !== undefined ? rawLivenessScore : defaultLivScore,
    0,
    1
  );
  const livenessConfidence = Number(
    (livenessDecision === 'FAILED'
      ? 0
      : livenessDecision === 'INCONCLUSIVE'
      ? Math.min(0.55, livenessScore)
      : livenessScore
    ).toFixed(3)
  );

  const thrMap: Record<ModalityName, number> = {
    face: assertFiniteInRange('thresholds.face', thresholds.face ?? 0.72, 0, 1),
    voice: assertFiniteInRange('thresholds.voice', thresholds.voice ?? 0.70, 0, 1),
    fingerprint: assertFiniteInRange('thresholds.fingerprint', thresholds.fingerprint ?? 0.72, 0, 1),
  };
  const threeModalThreshold = assertFiniteInRange('thresholds.threeModal', thresholds.threeModal ?? 0.74, 0, 1);

  const evaluateModality = (m: ModalityName): ModalityEvaluation | null => {
    const item = available[m];
    if (!item) return null;
    const rawScore = assertFiniteInRange(`available.${m}.score`, item.score, 0, 1);
    const rawQuality = assertFiniteInRange(`available.${m}.qualityScore`, item.qualityScore, 0, 100);
    if (item.rawCosine !== undefined) {
      assertFiniteInRange(`available.${m}.rawCosine`, item.rawCosine, -1, 1);
    }
    const thr = thrMap[m];
    const q = Math.round(rawQuality);
    const score = Number(rawScore.toFixed(4));
    const strongMismatch = score <= Math.max(0.20, thr - 0.16) || score < 0.36;
    const isInconclusive =
      item.inconclusive === true ||
      item.decision === 'INCONCLUSIVE' ||
      q < 40 ||
      (q < 55 && Math.abs(score - thr) <= 0.035);
    const passed = !isInconclusive && score >= thr;
    const status: ModalityStatus = isInconclusive ? 'INCONCLUSIVE' : passed ? 'MATCH' : 'NO MATCH';
    return {
      modality: m,
      score,
      rawCosine: item.rawCosine,
      threshold: thr,
      qualityScore: q,
      passed,
      inconclusive: isInconclusive,
      status,
      strongMismatch,
      details: item.details,
    };
  };

  let requested: ModalityName[] = [];
  let baseThreshold = thrMap.face;
  let stage: string | undefined;

  const strictLivenessDefault = livenessPolicy?.strictLiveness ?? true;
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
    baseThreshold = threeModalThreshold;
  } else {
    // hierarchical
    const fEval = evaluateModality('face');
    if (!fEval) {
      const msg = 'Hierarchical verification requires a face probe and enrolled face template.';
      return {
        pipeline,
        fusionPolicy,
        modalitiesEvaluated: [],
        modalityEvaluations: {},
        finalScore: 0,
        baseThreshold: thrMap.face,
        confidence: 0,
        identityConfidence: 0,
        sampleQualityScore: 0,
        livenessConfidence,
        confidenceBand: 'low',
        conflictDetected: false,
        conflictDetails: [],
        rejectionReasons: [msg],
        outcome: 'not_evaluated',
        finalDecision: 'INCONCLUSIVE',
        identityMatch: { passed: false, score: 0, threshold: thrMap.face, status: 'NOT EVALUATED' },
        livenessVerification: {
          status: livenessStatus,
          decision: livenessDecision,
          score: livenessScore,
          confidence: livenessConfidence,
          strictRequired: strictLivenessDefault,
        },
        livenessStatus,
        livenessDecision,
        fusionExplanation: msg,
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
        const msg = `Face similarity (${(fEval.score * 100).toFixed(1)}%) landed in the uncertain band (${(lowGate * 100).toFixed(0)}%–${(highGate * 100).toFixed(0)}%); secondary Voice or Fingerprint probe required.`;
        const fQual = Number((fEval.qualityScore / 100).toFixed(3));
        return {
          pipeline: 'hierarchical',
          fusionPolicy,
          modalitiesEvaluated: ['face'],
          modalityEvaluations: { face: fEval },
          finalScore: fEval.score,
          baseThreshold: thrMap.face,
          confidence: 0.35,
          identityConfidence: 0.35,
          sampleQualityScore: fQual,
          livenessConfidence,
          confidenceBand: 'low',
          conflictDetected: false,
          conflictDetails: [],
          rejectionReasons: [msg],
          outcome: 'not_evaluated',
          finalDecision: 'INCONCLUSIVE',
          identityMatch: { passed: false, score: fEval.score, threshold: thrMap.face, status: 'INCONCLUSIVE' },
          livenessVerification: {
            status: livenessStatus,
            decision: livenessDecision,
            score: livenessScore,
            confidence: livenessConfidence,
            strictRequired: strictLivenessDefault,
          },
          livenessStatus,
          livenessDecision,
          fusionExplanation: msg,
          reasonCode: 'hierarchical_uncertain_secondary_required',
          stage: 'Uncertain band — secondary factor required',
        };
      }
      baseThreshold =
        requested.length === 3
          ? threeModalThreshold
          : Number(((thrMap.face + (available.voice ? thrMap.voice : thrMap.fingerprint)) / 2).toFixed(4));
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
    const msg = `Missing required modality sample or enrolled template: ${missing.join(', ')}`;
    const partialQual = evals.length
      ? Number((evals.reduce((s, e) => s + e.qualityScore, 0) / evals.length / 100).toFixed(3))
      : 0;
    return {
      pipeline,
      fusionPolicy,
      modalitiesEvaluated: evals.map((e) => e.modality),
      modalityEvaluations: evalMap,
      finalScore: 0,
      baseThreshold,
      confidence: 0,
      identityConfidence: 0,
      sampleQualityScore: partialQual,
      livenessConfidence,
      confidenceBand: 'low',
      conflictDetected: false,
      conflictDetails: [],
      rejectionReasons: [msg],
      outcome: 'not_evaluated',
      finalDecision: 'INCONCLUSIVE',
      identityMatch: { passed: false, score: 0, threshold: baseThreshold, status: 'NOT EVALUATED' },
      livenessVerification: {
        status: livenessStatus,
        decision: livenessDecision,
        score: livenessScore,
        confidence: livenessConfidence,
        strictRequired: strictLivenessDefault,
      },
      livenessStatus,
      livenessDecision,
      fusionExplanation: msg,
      reasonCode: 'missing_template_or_sample',
      stage,
    };
  }

  // Quality-weighted fusion using normalized configured modalityWeights
  let baseWeightSum = 0;
  for (const ev of evals) {
    baseWeightSum += getBaseWeight(ev.modality, modalityWeights);
  }
  let weightSum = 0;
  let weightedScoreSum = 0;
  for (const ev of evals) {
    const normBaseWeight = baseWeightSum > 0 ? getBaseWeight(ev.modality, modalityWeights) / baseWeightSum : 1 / evals.length;
    const qFactor = 0.5 + 0.5 * (ev.qualityScore / 100);
    const w = normBaseWeight * qFactor;
    weightSum += w;
    weightedScoreSum += w * ev.score;
  }
  const finalScore = Number((weightSum > 0 ? weightedScoreSum / weightSum : 0).toFixed(4));

  // Conflict Detection: strong mismatch on one modality blocks override by another
  const conflictDetails: string[] = [];
  const rejectionReasons: string[] = [];
  const passing = evals.filter((e) => e.passed);
  const failing = evals.filter((e) => !e.passed);
  const inconclusiveMods = evals.filter((e) => e.inconclusive);
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

  const strictLivenessRequired =
    livenessPolicy?.strictLiveness !== false ||
    Boolean(
      livenessPolicy?.requiredModalities &&
        evals.some((e) => livenessPolicy.requiredModalities?.includes(e.modality))
    );

  // Compute independent Identity Match assessment (strictly separated from Liveness Verification)
  let identityMatchPassed = false;
  let identityMatchStatus: ModalityStatus = 'NO MATCH';
  if (conflictDetected || strongMismatches.length > 0) {
    identityMatchPassed = false;
    identityMatchStatus = 'NO MATCH';
  } else if (inconclusiveMods.length === evals.length || (inconclusiveMods.length > 0 && (evals.length === 1 || fusionPolicy === 'strict_and'))) {
    identityMatchPassed = false;
    identityMatchStatus = 'INCONCLUSIVE';
  } else if (fusionPolicy === 'strict_and') {
    identityMatchPassed = failing.length === 0 && finalScore >= baseThreshold;
    identityMatchStatus = identityMatchPassed ? 'MATCH' : 'NO MATCH';
  } else if (finalScore >= baseThreshold && inconclusiveMods.length === 0) {
    identityMatchPassed = true;
    identityMatchStatus = 'MATCH';
  } else if (finalScore >= baseThreshold && inconclusiveMods.length > 0) {
    identityMatchPassed = false;
    identityMatchStatus = 'INCONCLUSIVE';
  } else {
    identityMatchPassed = false;
    identityMatchStatus = 'NO MATCH';
  }

  // Determine 3-state Final Decision: VERIFIED | REJECTED | INCONCLUSIVE
  let outcome: 'match' | 'no_match' | 'not_evaluated' = 'no_match';
  let finalDecision: FinalDecision = 'REJECTED';
  let reasonCode = `${pipeline}_match`;

  if (livenessDecision === 'FAILED') {
    outcome = 'no_match';
    finalDecision = 'REJECTED';
    reasonCode = 'spoof_or_liveness_failed';
    rejectionReasons.push('Liveness / anti-spoofing check failed.');
  } else if (conflictDetected) {
    outcome = 'no_match';
    finalDecision = 'REJECTED';
    reasonCode = 'conflicting_biometric_evidence';
    rejectionReasons.push(...conflictDetails);
  } else if (strongMismatches.length > 0) {
    outcome = 'no_match';
    finalDecision = 'REJECTED';
    reasonCode = `${strongMismatches[0].modality}_strong_mismatch`;
    for (const sm of strongMismatches) {
      rejectionReasons.push(`${sm.modality} showed strong mismatch (${(sm.score * 100).toFixed(1)}%).`);
    }
  } else if (inconclusiveMods.length > 0 && (evals.length === 1 || fusionPolicy === 'strict_and')) {
    outcome = 'not_evaluated';
    finalDecision = 'INCONCLUSIVE';
    reasonCode = `${inconclusiveMods[0].modality}_inconclusive`;
    for (const inc of inconclusiveMods) {
      rejectionReasons.push(
        `${inc.modality} probe returned INCONCLUSIVE (quality ${inc.qualityScore}/100, similarity ${(inc.score * 100).toFixed(1)}%). Recapture required.`
      );
    }
  } else if (strictLivenessRequired && livenessDecision !== 'PASSED') {
    outcome = 'not_evaluated';
    finalDecision = 'INCONCLUSIVE';
    reasonCode = 'liveness_inconclusive_blocked';
    rejectionReasons.push(
      `Strict liveness policy requires confirmed LIVENESS PASSED (current liveness status: ${livenessStatus}; identity similarity ${(finalScore * 100).toFixed(1)}%).`
    );
  } else if (fusionPolicy === 'strict_and') {
    if (failing.length === 0 && finalScore >= baseThreshold) {
      outcome = 'match';
      finalDecision = 'VERIFIED';
      reasonCode = `${pipeline}_strict_match`;
    } else {
      outcome = 'no_match';
      finalDecision = 'REJECTED';
      reasonCode = 'strict_policy_modality_failed';
      for (const f of failing) {
        rejectionReasons.push(`${f.modality} similarity (${(f.score * 100).toFixed(1)}%) fell below ${(f.threshold * 100).toFixed(0)}% threshold.`);
      }
      if (finalScore < baseThreshold) {
        rejectionReasons.push(`Fused similarity (${(finalScore * 100).toFixed(1)}%) fell below ${(baseThreshold * 100).toFixed(0)}% policy threshold.`);
      }
    }
  } else {
    // weighted_score or hierarchical_adaptive: inconclusive modality cannot approve on its own
    if (inconclusiveMods.length === evals.length) {
      outcome = 'not_evaluated';
      finalDecision = 'INCONCLUSIVE';
      reasonCode = 'all_modalities_inconclusive';
      rejectionReasons.push('All submitted modalities returned INCONCLUSIVE quality or borderline evidence.');
    } else if (finalScore >= baseThreshold && inconclusiveMods.length === 0) {
      outcome = 'match';
      finalDecision = 'VERIFIED';
      reasonCode = stage?.includes('Stage 1') ? 'hierarchical_stage1_face_match' : `${pipeline}_match`;
    } else if (finalScore >= baseThreshold && inconclusiveMods.length > 0) {
      outcome = 'not_evaluated';
      finalDecision = 'INCONCLUSIVE';
      reasonCode = 'partial_inconclusive_escalation';
      rejectionReasons.push(
        `Weighted similarity reached ${(finalScore * 100).toFixed(1)}%, but ${inconclusiveMods.map((i) => i.modality).join(', ')} returned INCONCLUSIVE.`
      );
    } else {
      outcome = 'no_match';
      finalDecision = 'REJECTED';
      reasonCode = `${pipeline}_below_threshold`;
      rejectionReasons.push(`Fused similarity (${(finalScore * 100).toFixed(1)}%) fell below ${(baseThreshold * 100).toFixed(0)}% threshold.`);
      for (const f of failing) {
        rejectionReasons.push(`${f.modality} scored ${(f.score * 100).toFixed(1)}% (threshold ${(f.threshold * 100).toFixed(0)}%).`);
      }
    }
  }

  // Separated Confidence Breakdowns (distinct from calibrated similarity score)
  const margin = Math.abs(finalScore - baseThreshold);
  const marginFactor = Math.min(1, margin / 0.22);
  const sampleQualityScore = Number((evals.reduce((s, e) => s + e.qualityScore, 0) / evals.length / 100).toFixed(3));
  const agreementFactor = conflictDetected ? 0.25 : evals.length >= 2 && failing.length === 0 ? 1.0 : 0.78;
  const identityConfidence = Number(
    Math.max(0.05, Math.min(0.99, (0.78 * marginFactor + 0.22 * agreementFactor) * (conflictDetected ? 0.55 : 1))).toFixed(3)
  );
  const rawConf = 0.45 * marginFactor + 0.30 * sampleQualityScore + 0.15 * livenessConfidence + 0.10 * agreementFactor;
  const confidence = Number(
    Math.max(0.05, Math.min(0.99, conflictDetected || finalDecision === 'INCONCLUSIVE' ? rawConf * 0.65 : rawConf)).toFixed(3)
  );
  const confidenceBand: 'high' | 'moderate' | 'low' =
    confidence >= 0.75 ? 'high' : confidence >= 0.48 ? 'moderate' : 'low';

  const modSummary = evals.map((e) => `${e.modality}: ${e.status} (${(e.score * 100).toFixed(1)}%)`).join(', ');
  const fusionExplanation =
    finalDecision === 'VERIFIED'
      ? `VERIFIED under ${fusionPolicy} policy. Fused score ${(finalScore * 100).toFixed(1)}% met threshold ${(baseThreshold * 100).toFixed(0)}% across [${modSummary}]. Liveness status: ${livenessStatus}.`
      : finalDecision === 'INCONCLUSIVE'
      ? `INCONCLUSIVE outcome (${reasonCode}). ${rejectionReasons[0] || `Evaluated [${modSummary}].`} Identity match: ${identityMatchStatus}; Liveness: ${livenessStatus}.`
      : `REJECTED under ${fusionPolicy} policy (${reasonCode}). ${rejectionReasons[0] || `Fused score ${(finalScore * 100).toFixed(1)}% vs ${(baseThreshold * 100).toFixed(0)}% threshold.`} [${modSummary}].`;

  return {
    pipeline,
    fusionPolicy,
    modalitiesEvaluated: evals.map((e) => e.modality),
    modalityEvaluations: evalMap,
    finalScore,
    baseThreshold,
    confidence,
    identityConfidence,
    sampleQualityScore,
    livenessConfidence,
    confidenceBand,
    conflictDetected,
    conflictDetails,
    rejectionReasons,
    outcome,
    finalDecision,
    identityMatch: {
      passed: identityMatchPassed,
      score: finalScore,
      threshold: baseThreshold,
      status: identityMatchStatus,
    },
    livenessVerification: {
      status: livenessStatus,
      decision: livenessDecision,
      score: livenessScore,
      confidence: livenessConfidence,
      strictRequired: strictLivenessRequired,
    },
    livenessStatus,
    livenessDecision,
    fusionExplanation,
    reasonCode,
    stage,
  };
}


