// Shared Biometric Statistics & Performance Evaluation Engine
// Strictly enforces:
// 1. Model Similarity Score != Identity Probability
// 2. Measured Classification Accuracy MUST come from labeled ground-truth trials
//    (groundTruth === 'genuine' | 'impostor'), NEVER inferred from predicted outcome === 'match'
// 3. Operational Verification Success Rate is tracked separately from Classification Accuracy
// 4. Wilson Score 95% confidence intervals & insufficient-data guards

export interface GroundTruthTrial {
  score: number;
  genuine: boolean;
  modality?: 'face' | 'voice' | 'fingerprint' | 'multimodal';
  threshold?: number;
  isTestProbe?: boolean;
  timestampMs?: number;
}

export interface ConfidenceInterval {
  low: number;
  high: number;
}

export interface ClassificationMetricsResult {
  sampleCount: number;
  genuineCount: number;
  impostorCount: number;
  insufficientData: boolean;
  insufficientReason: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  accuracy: number;
  tar: number; // True Acceptance Rate = GAR = Recall = 1 - FRR
  gar: number;
  far: number; // False Acceptance Rate = IAR
  iar: number;
  frr: number; // False Rejection Rate
  precision: number;
  recall: number;
  f1: number;
  eer: number;
  eerThreshold: number;
  auc: number;
  roc: Array<{ thr: number; far: number; frr: number; tpr: number }>;
  ci95: {
    accuracy: ConfidenceInterval;
    tar: ConfidenceInterval;
    far: ConfidenceInterval;
    frr: ConfidenceInterval;
  };
}

// Wilson Score 95% Confidence Interval (z = 1.96)
export function wilsonCI95(successes: number, total: number): ConfidenceInterval {
  if (total <= 0) return { low: 0, high: 0 };
  const z = 1.96;
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p)) / total + z2 / (4 * total * total))) / denom;
  return {
    low: Number(Math.max(0, center - margin).toFixed(4)),
    high: Number(Math.min(1, center + margin).toFixed(4)),
  };
}

export function computeClassificationMetrics(
  trials: GroundTruthTrial[],
  threshold = 0.72
): ClassificationMetricsResult {
  const genuineTrials = trials.filter((t) => t.genuine === true);
  const impostorTrials = trials.filter((t) => t.genuine === false);
  const genuineCount = genuineTrials.length;
  const impostorCount = impostorTrials.length;
  const sampleCount = trials.length;
  const insufficientData = genuineCount < 3 || impostorCount < 3;

  let insufficientReason = '';
  if (sampleCount === 0) {
    insufficientReason = 'No ground-truth labeled verification trials exist in the selected range.';
  } else if (genuineCount < 3 && impostorCount < 3) {
    insufficientReason = `Need at least 3 genuine and 3 impostor labeled trials for reliable accuracy/EER bounds (found ${genuineCount} genuine, ${impostorCount} impostor).`;
  } else if (genuineCount < 3) {
    insufficientReason = `Need at least 3 genuine labeled trials to estimate TAR/FRR reliably (found ${genuineCount}).`;
  } else if (impostorCount < 3) {
    insufficientReason = `Need at least 3 impostor labeled trials to estimate FAR/IAR reliably (found ${impostorCount}).`;
  }

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const t of trials) {
    const thr = typeof t.threshold === 'number' ? t.threshold : threshold;
    const pred = t.score >= thr;
    if (t.genuine && pred) tp++;
    else if (!t.genuine && pred) fp++;
    else if (!t.genuine && !pred) tn++;
    else fn++;
  }

  const accuracy = sampleCount ? (tp + tn) / sampleCount : 0;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const tar = recall;
  const gar = recall;
  const far = fp + tn ? fp / (fp + tn) : 0;
  const iar = far;
  const frr = fn + tp ? fn / (fn + tp) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

  const roc: Array<{ thr: number; far: number; frr: number; tpr: number }> = [];
  let bestEerDiff = 2;
  let eer = 0;
  let eerThreshold = threshold;

  if (genuineCount > 0 && impostorCount > 0) {
    for (let step = 0; step <= 100; step++) {
      const thr = step / 100;
      let sTp = 0, sFp = 0, sTn = 0, sFn = 0;
      for (const t of trials) {
        const p = t.score >= thr;
        if (t.genuine && p) sTp++;
        else if (!t.genuine && p) sFp++;
        else if (!t.genuine && !p) sTn++;
        else sFn++;
      }
      const sFar = sFp + sTn ? sFp / (sFp + sTn) : 0;
      const sFrr = sFn + sTp ? sFn / (sFn + sTp) : 0;
      const tpr = 1 - sFrr;
      roc.push({ thr, far: sFar, frr: sFrr, tpr });
      const diff = Math.abs(sFar - sFrr);
      if (diff < bestEerDiff) {
        bestEerDiff = diff;
        eer = (sFar + sFrr) / 2;
        eerThreshold = thr;
      }
    }
  }

  const sorted = [...roc].sort((a, b) => a.far - b.far);
  let auc = 0;
  for (let i = 1; i < sorted.length; i++) {
    auc += ((sorted[i].far - sorted[i - 1].far) * (sorted[i].tpr + sorted[i - 1].tpr)) / 2;
  }

  return {
    sampleCount,
    genuineCount,
    impostorCount,
    insufficientData,
    insufficientReason,
    tp,
    fp,
    tn,
    fn,
    accuracy: Number(accuracy.toFixed(4)),
    tar: Number(tar.toFixed(4)),
    gar: Number(gar.toFixed(4)),
    far: Number(far.toFixed(4)),
    iar: Number(iar.toFixed(4)),
    frr: Number(frr.toFixed(4)),
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1: Number(f1.toFixed(4)),
    eer: Number(eer.toFixed(4)),
    eerThreshold: Number(eerThreshold.toFixed(2)),
    auc: Number(Math.min(1, Math.max(0, auc)).toFixed(4)),
    roc,
    ci95: {
      accuracy: wilsonCI95(tp + tn, sampleCount),
      tar: wilsonCI95(tp, tp + fn),
      far: wilsonCI95(fp, fp + tn),
      frr: wilsonCI95(fn, tp + fn),
    },
  };
}

export interface VerificationRecordLike {
  verificationId?: string;
  identityRef?: string;
  modalities?: string[];
  pipeline?: string;
  outcome?: string;
  reasonCode?: string;
  score?: number;
  confidence?: number;
  riskScore?: number;
  riskLevel?: string;
  livenessPassed?: boolean;
  livenessScore?: number;
  conflictDetected?: boolean;
  processingTimeMs?: number;
  groundTruth?: 'genuine' | 'impostor' | 'unlabeled';
  isTestProbe?: boolean;
  faceScore?: number;
  voiceScore?: number;
  fingerprintScore?: number;
  createdAt?: { toMillis?: () => number } | string | number;
}

export function extractTimestampMs(ts: VerificationRecordLike['createdAt']): number {
  if (!ts) return 0;
  if (typeof ts === 'number') return ts;
  if (typeof ts === 'string') {
    const parsed = Date.parse(ts);
    return Number.isNaN(parsed) ? 0 : parsed;
  }
  if (typeof ts === 'object' && typeof ts.toMillis === 'function') {
    return ts.toMillis();
  }
  return 0;
}

export interface ComprehensiveAnalyticsReport {
  totalIdentities: number;
  activeIdentities: number;
  totalAttempts: number;
  operationalAttempts: number;
  testProbeAttempts: number;
  labeledAttempts: number;
  unlabeledAttempts: number;
  successfulVerifications: number;
  rejectedVerifications: number;
  notEvaluatedVerifications: number;
  operationalVerificationSuccessRate: number; // Match / Evaluated operational attempts
  livenessKnownCount: number;
  livenessSuccessRate: number;
  conflictCount: number;
  avgRiskScore: number | null;
  latency: {
    measuredCount: number;
    avgMs: number | null;
    p50Ms: number | null;
    p95Ms: number | null;
    maxMs: number | null;
  };
  dateRange: {
    startMs: number | null;
    endMs: number | null;
  };
  classification: ClassificationMetricsResult;
  perModality: Record<'face' | 'voice' | 'fingerprint' | 'multimodal', {
    totalEvaluations: number;
    meanSimilarity: number | null;
    labeledCount: number;
    metrics: ClassificationMetricsResult | null;
  }>;
  failedBreakdown: Array<{ reasonCode: string; count: number }>;
  methodologyNote: string;
}

export function buildBiometricAnalyticsReport(
  records: VerificationRecordLike[],
  identitiesCount: number,
  activeIdentitiesCount: number,
  defaultThresholds: { face?: number; voice?: number; fingerprint?: number; threeModal?: number } = {}
): ComprehensiveAnalyticsReport {
  const fThr = defaultThresholds.face ?? 0.72;
  const vThr = defaultThresholds.voice ?? 0.70;
  const fpThr = defaultThresholds.fingerprint ?? 0.72;
  const mThr = defaultThresholds.threeModal ?? 0.74;

  const operational = records.filter((r) => !r.isTestProbe);
  const testProbes = records.filter((r) => r.isTestProbe === true);

  const labeled = records.filter(
    (r) =>
      (r.groundTruth === 'genuine' || r.groundTruth === 'impostor') &&
      (r.outcome === 'match' || r.outcome === 'no_match')
  );
  const unlabeled = records.filter((r) => r.groundTruth !== 'genuine' && r.groundTruth !== 'impostor');

  const evaluatedAll = records.filter((r) => r.outcome === 'match' || r.outcome === 'no_match');
  const successful = records.filter((r) => r.outcome === 'match').length;
  const rejected = records.filter((r) => r.outcome === 'no_match').length;
  const notEvaluated = records.filter((r) => r.outcome === 'not_evaluated').length;

  const evalOp = operational.filter((r) => r.outcome === 'match' || r.outcome === 'no_match');
  const opMatches = evalOp.filter((r) => r.outcome === 'match').length;
  const operationalVerificationSuccessRate = evalOp.length
    ? Number((opMatches / evalOp.length).toFixed(4))
    : evaluatedAll.length
    ? Number((successful / evaluatedAll.length).toFixed(4))
    : 0;

  const liveKnown = records.filter((r) => typeof r.livenessPassed === 'boolean');
  const livePass = liveKnown.filter((r) => r.livenessPassed === true).length;
  const livenessSuccessRate = liveKnown.length ? Number((livePass / liveKnown.length).toFixed(4)) : 0;

  const riskKnown = records.filter((r) => typeof r.riskScore === 'number');
  const avgRiskScore = riskKnown.length
    ? Number((riskKnown.reduce((s, r) => s + (r.riskScore || 0), 0) / riskKnown.length).toFixed(1))
    : null;

  const latencies = records
    .map((r) => r.processingTimeMs)
    .filter((x): x is number => typeof x === 'number' && Number.isFinite(x) && x >= 0)
    .sort((a, b) => a - b);
  const latency = latencies.length
    ? {
        measuredCount: latencies.length,
        avgMs: Number((latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1)),
        p50Ms: Number(latencies[Math.floor(latencies.length * 0.5)].toFixed(1)),
        p95Ms: Number(latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95))].toFixed(1)),
        maxMs: Number(latencies[latencies.length - 1].toFixed(1)),
      }
    : { measuredCount: 0, avgMs: null, p50Ms: null, p95Ms: null, maxMs: null };

  const times = records.map((r) => extractTimestampMs(r.createdAt)).filter((t) => t > 0);
  const dateRange = {
    startMs: times.length ? Math.min(...times) : null,
    endMs: times.length ? Math.max(...times) : null,
  };

  // Classification metrics strictly from groundTruth === 'genuine' | 'impostor'
  const overallTrials: GroundTruthTrial[] = labeled.map((r) => ({
    score: Number(r.score || 0),
    genuine: r.groundTruth === 'genuine',
    threshold:
      r.pipeline === 'voice_only' || r.pipeline === 'voice'
        ? vThr
        : r.pipeline === 'fingerprint_only' || r.pipeline === 'fingerprint'
        ? fpThr
        : r.pipeline === 'three_modal'
        ? mThr
        : fThr,
    isTestProbe: r.isTestProbe,
    timestampMs: extractTimestampMs(r.createdAt),
  }));
  const classification = computeClassificationMetrics(overallTrials, fThr);

  const buildModSummary = (mod: 'face' | 'voice' | 'fingerprint' | 'multimodal') => {
    const thr = mod === 'face' ? fThr : mod === 'voice' ? vThr : mod === 'fingerprint' ? fpThr : mThr;
    const modRecs = records.filter((r) => {
      const mods = r.modalities || [];
      if (mod === 'multimodal') return mods.length >= 2;
      if (mod === 'face') return typeof r.faceScore === 'number' || mods.includes('face');
      if (mod === 'voice') return typeof r.voiceScore === 'number' || mods.includes('voice');
      return typeof r.fingerprintScore === 'number' || mods.includes('fingerprint');
    });

    const sims = modRecs
      .map((r) => {
        if (mod === 'face' && typeof r.faceScore === 'number') return r.faceScore;
        if (mod === 'voice' && typeof r.voiceScore === 'number') return r.voiceScore;
        if (mod === 'fingerprint' && typeof r.fingerprintScore === 'number') return r.fingerprintScore;
        if (mod === 'multimodal' && (r.modalities?.length || 0) >= 2 && typeof r.score === 'number') return r.score;
        if ((r.modalities?.length || 0) === 1 && r.modalities?.[0] === mod && typeof r.score === 'number') return r.score;
        return null;
      })
      .filter((x): x is number => typeof x === 'number');

    const meanSimilarity = sims.length ? Number((sims.reduce((a, b) => a + b, 0) / sims.length).toFixed(4)) : null;

    const modTrials: GroundTruthTrial[] = [];
    for (const r of labeled) {
      let s: number | null = null;
      if (mod === 'face' && typeof r.faceScore === 'number') s = r.faceScore;
      else if (mod === 'voice' && typeof r.voiceScore === 'number') s = r.voiceScore;
      else if (mod === 'fingerprint' && typeof r.fingerprintScore === 'number') s = r.fingerprintScore;
      else if (mod === 'multimodal' && (r.modalities?.length || 0) >= 2 && typeof r.score === 'number') s = r.score;
      else if ((r.modalities?.length || 0) === 1 && r.modalities?.[0] === mod && typeof r.score === 'number') s = r.score;
      if (s !== null) {
        modTrials.push({ score: s, genuine: r.groundTruth === 'genuine', threshold: thr });
      }
    }

    return {
      totalEvaluations: modRecs.length,
      meanSimilarity,
      labeledCount: modTrials.length,
      metrics: modTrials.length > 0 ? computeClassificationMetrics(modTrials, thr) : null,
    };
  };

  const failCounts = new Map<string, number>();
  for (const r of records) {
    if (r.outcome === 'no_match' || r.outcome === 'not_evaluated') {
      const code = r.reasonCode || 'unknown';
      failCounts.set(code, (failCounts.get(code) || 0) + 1);
    }
  }
  const failedBreakdown = [...failCounts.entries()]
    .map(([reasonCode, count]) => ({ reasonCode, count }))
    .sort((a, b) => b.count - a.count);

  return {
    totalIdentities: identitiesCount,
    activeIdentities: activeIdentitiesCount,
    totalAttempts: records.length,
    operationalAttempts: operational.length,
    testProbeAttempts: testProbes.length,
    labeledAttempts: labeled.length,
    unlabeledAttempts: unlabeled.length,
    successfulVerifications: successful,
    rejectedVerifications: rejected,
    notEvaluatedVerifications: notEvaluated,
    operationalVerificationSuccessRate,
    livenessKnownCount: liveKnown.length,
    livenessSuccessRate,
    conflictCount: records.filter((r) => r.conflictDetected === true).length,
    avgRiskScore,
    latency,
    dateRange,
    classification,
    perModality: {
      face: buildModSummary('face'),
      voice: buildModSummary('voice'),
      fingerprint: buildModSummary('fingerprint'),
      multimodal: buildModSummary('multimodal'),
    },
    failedBreakdown,
    methodologyNote:
      'Classification Accuracy, TAR/GAR, FAR/IAR, FRR, Precision, Recall, F1, EER, and Wilson 95% CIs are computed exclusively from ground-truth labeled trials (genuine vs impostor), never from predicted outcomes. Unlabeled operational verifications report Operational Match Rate separately.',
  };
}
