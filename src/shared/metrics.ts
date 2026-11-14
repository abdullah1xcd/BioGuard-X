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
  finalDecision?: 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';
  reasonCode?: string;
  score?: number;
  confidence?: number;
  riskScore?: number;
  riskLevel?: string;
  livenessPassed?: boolean;
  livenessStatus?: string;
  livenessScore?: number;
  conflictDetected?: boolean;
  processingTimeMs?: number;
  groundTruth?: 'genuine' | 'impostor' | 'unlabeled';
  datasetCategory?: 'operational' | 'synthetic_qa' | 'benchmark_eval';
  isTestProbe?: boolean;
  subjectKey?: string;
  partition?: 'train' | 'eval' | 'unassigned';
  sampleHash?: string;
  benchmarkBatchId?: string;
  provenanceSignature?: string;
  captureFailure?: boolean;
  faceScore?: number;
  voiceScore?: number;
  fingerprintScore?: number;
  faceQuality?: number;
  voiceQuality?: number;
  fingerprintQuality?: number;
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

export interface OperationalDatasetReport {
  totalAttempts: number;
  verifiedCount: number;
  rejectedCount: number;
  inconclusiveCount: number;
  captureFailureCount: number;
  captureFailureRate: number | null;
  operationalMatchRate: number | null;
  livenessPassedCount: number;
  livenessFailedCount: number;
  livenessInconclusiveCount: number;
  livenessNotSupportedCount: number;
  avgProcessingTimeMs: number | null;
  avgRiskScore: number | null;
}

export interface SyntheticQaDatasetReport {
  totalProbes: number;
  genuineProbes: number;
  impostorProbes: number;
  verifiedCount: number;
  rejectedCount: number;
  inconclusiveCount: number;
  classification: ClassificationMetricsResult;
}

export interface BenchmarkDatasetReport {
  totalLabeledTrials: number;
  operationalLabeledTrials: number;
  syntheticLabeledTrials: number;
  duplicateExcludedCount: number;
  subjectOverlapDetected: boolean;
  insufficientData: boolean;
  insufficientDataMessage: string;
  classification: ClassificationMetricsResult;
  operationalOnlyClassification: ClassificationMetricsResult | null;
}

export interface SampleQualityDistribution {
  measuredCount: number;
  goodCount: number;
  borderlineCount: number;
  poorCount: number;
  meanQuality: number | null;
}

export interface LivenessBreakdown {
  passed: number;
  failed: number;
  inconclusive: number;
  notSupported: number;
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
  inconclusiveRate: number;
  captureFailureCount: number;
  captureFailureRate: number;
  operationalVerificationSuccessRate: number; // Match / Evaluated operational attempts
  livenessKnownCount: number;
  livenessSuccessRate: number;
  livenessFailureRate: number;
  livenessBreakdown: LivenessBreakdown;
  sampleQualityDistribution: SampleQualityDistribution;
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
  datasets: {
    operational: OperationalDatasetReport;
    syntheticQa: SyntheticQaDatasetReport;
    benchmark: BenchmarkDatasetReport;
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

function isCaptureFailureRecord(r: VerificationRecordLike): boolean {
  if (r.captureFailure === true) return true;
  if (r.outcome === 'not_evaluated' || r.finalDecision === 'INCONCLUSIVE') return true;
  const rc = String(r.reasonCode || '').toLowerCase();
  return (
    rc.includes('inconclusive') ||
    rc.includes('quality_check_failed') ||
    rc.includes('blurry') ||
    rc.includes('too_short') ||
    rc.includes('insufficient')
  );
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

  const operational = records.filter(
    (r) => !r.isTestProbe && r.datasetCategory !== 'synthetic_qa' && r.datasetCategory !== 'benchmark_eval'
  );
  const testProbes = records.filter((r) => r.isTestProbe === true || r.datasetCategory === 'synthetic_qa');

  const rawBenchmarkEval = records.filter(
    (r) =>
      r.datasetCategory === 'benchmark_eval' &&
      r.isTestProbe !== true &&
      (r.groundTruth === 'genuine' || r.groundTruth === 'impostor') &&
      (r.outcome === 'match' || r.outcome === 'no_match')
  );

  const trainSubjects = new Set(
    rawBenchmarkEval
      .filter((r) => r.partition === 'train' && typeof r.subjectKey === 'string' && r.subjectKey.trim())
      .map((r) => r.subjectKey!.trim())
  );
  const evalSubjects = new Set(
    rawBenchmarkEval
      .filter((r) => r.partition !== 'train' && typeof r.subjectKey === 'string' && r.subjectKey.trim())
      .map((r) => r.subjectKey!.trim())
  );
  const subjectOverlapDetected = [...evalSubjects].some((sk) => trainSubjects.has(sk));

  const seenHashes = new Set<string>();
  const benchmarkEval: VerificationRecordLike[] = [];
  let duplicateExcludedCount = 0;
  for (const r of rawBenchmarkEval) {
    if (r.partition === 'train') continue;
    const hashKey = r.sampleHash ? `${r.identityRef || ''}:${r.sampleHash}:${r.groundTruth}` : '';
    if (hashKey && seenHashes.has(hashKey)) {
      duplicateExcludedCount++;
      continue;
    }
    if (hashKey) seenHashes.add(hashKey);
    benchmarkEval.push(r);
  }

  const labeledQa = testProbes.filter(
    (r) =>
      (r.groundTruth === 'genuine' || r.groundTruth === 'impostor') &&
      (r.outcome === 'match' || r.outcome === 'no_match')
  );
  const unlabeled = records.filter(
    (r) => r.datasetCategory !== 'benchmark_eval' || (r.groundTruth !== 'genuine' && r.groundTruth !== 'impostor')
  );

  const evaluatedAll = records.filter((r) => r.outcome === 'match' || r.outcome === 'no_match');
  const successful = records.filter((r) => r.outcome === 'match').length;
  const rejected = records.filter((r) => r.outcome === 'no_match').length;
  const notEvaluated = records.filter((r) => r.outcome === 'not_evaluated' || r.finalDecision === 'INCONCLUSIVE').length;
  const inconclusiveRate = records.length ? Number((notEvaluated / records.length).toFixed(4)) : 0;
  const captureFailureCount = records.filter(isCaptureFailureRecord).length;
  const captureFailureRate = records.length ? Number((captureFailureCount / records.length).toFixed(4)) : 0;

  const evalOp = operational.filter((r) => r.outcome === 'match' || r.outcome === 'no_match');
  const opMatches = evalOp.filter((r) => r.outcome === 'match').length;
  const opRejects = evalOp.filter((r) => r.outcome === 'no_match').length;
  const opInconclusive = operational.filter((r) => r.outcome === 'not_evaluated' || r.finalDecision === 'INCONCLUSIVE').length;
  const opCapFail = operational.filter(isCaptureFailureRecord).length;
  const operationalVerificationSuccessRate = evalOp.length
    ? Number((opMatches / evalOp.length).toFixed(4))
    : 0;

  const livePassed = records.filter((r) => r.livenessStatus === 'LIVENESS PASSED' || (!r.livenessStatus && r.livenessPassed === true)).length;
  const liveFailed = records.filter((r) => r.livenessStatus === 'LIVENESS FAILED' || (!r.livenessStatus && r.livenessPassed === false)).length;
  const liveInconclusive = records.filter((r) => r.livenessStatus === 'INCONCLUSIVE').length;
  const liveNotSupported = records.filter((r) => r.livenessStatus === 'NOT SUPPORTED').length;
  const liveKnownCount = livePassed + liveFailed;
  const livenessSuccessRate = liveKnownCount ? Number((livePassed / liveKnownCount).toFixed(4)) : 0;
  const livenessFailureRate = liveKnownCount ? Number((liveFailed / liveKnownCount).toFixed(4)) : 0;

  const qualitySamples: number[] = [];
  for (const r of records) {
    for (const qVal of [r.faceQuality, r.voiceQuality, r.fingerprintQuality]) {
      if (typeof qVal === 'number' && Number.isFinite(qVal) && qVal >= 0 && qVal <= 100) {
        qualitySamples.push(qVal);
      }
    }
  }
  const sampleQualityDistribution: SampleQualityDistribution = {
    measuredCount: qualitySamples.length,
    goodCount: qualitySamples.filter((q) => q >= 65).length,
    borderlineCount: qualitySamples.filter((q) => q >= 40 && q < 65).length,
    poorCount: qualitySamples.filter((q) => q < 40).length,
    meanQuality: qualitySamples.length
      ? Number((qualitySamples.reduce((a, b) => a + b, 0) / qualitySamples.length).toFixed(1))
      : null,
  };

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

  const toTrials = (list: VerificationRecordLike[]): GroundTruthTrial[] =>
    list.map((r) => ({
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

  const overallTrials = toTrials(benchmarkEval);
  const classification = computeClassificationMetrics(overallTrials, fThr);
  if (subjectOverlapDetected) {
    classification.insufficientData = true;
    classification.insufficientReason = 'Train and eval benchmark splits contain overlapping subjectKey values.';
  } else if (classification.insufficientData) {
    classification.insufficientReason = 'Real-world biometric accuracy has not yet been established.';
  }
  const opOnlyClassification = benchmarkEval.length > 0 ? classification : null;
  const qaClassification = computeClassificationMetrics(toTrials(labeledQa), fThr);

  const opLatencies = operational
    .map((r) => r.processingTimeMs)
    .filter((x): x is number => typeof x === 'number' && Number.isFinite(x) && x >= 0);
  const opRisks = operational.filter((r) => typeof r.riskScore === 'number');

  const operationalReport: OperationalDatasetReport = {
    totalAttempts: operational.length,
    verifiedCount: opMatches,
    rejectedCount: opRejects,
    inconclusiveCount: opInconclusive,
    captureFailureCount: opCapFail,
    captureFailureRate: operational.length ? Number((opCapFail / operational.length).toFixed(4)) : null,
    operationalMatchRate: evalOp.length ? Number((opMatches / evalOp.length).toFixed(4)) : null,
    livenessPassedCount: operational.filter((r) => r.livenessStatus === 'LIVENESS PASSED' || (!r.livenessStatus && r.livenessPassed === true)).length,
    livenessFailedCount: operational.filter((r) => r.livenessStatus === 'LIVENESS FAILED' || (!r.livenessStatus && r.livenessPassed === false)).length,
    livenessInconclusiveCount: operational.filter((r) => r.livenessStatus === 'INCONCLUSIVE').length,
    livenessNotSupportedCount: operational.filter((r) => r.livenessStatus === 'NOT SUPPORTED').length,
    avgProcessingTimeMs: opLatencies.length ? Number((opLatencies.reduce((a, b) => a + b, 0) / opLatencies.length).toFixed(1)) : null,
    avgRiskScore: opRisks.length ? Number((opRisks.reduce((s, r) => s + (r.riskScore || 0), 0) / opRisks.length).toFixed(1)) : null,
  };

  const syntheticQaReport: SyntheticQaDatasetReport = {
    totalProbes: testProbes.length,
    genuineProbes: testProbes.filter((r) => r.groundTruth === 'genuine').length,
    impostorProbes: testProbes.filter((r) => r.groundTruth === 'impostor').length,
    verifiedCount: testProbes.filter((r) => r.outcome === 'match').length,
    rejectedCount: testProbes.filter((r) => r.outcome === 'no_match').length,
    inconclusiveCount: testProbes.filter((r) => r.outcome === 'not_evaluated' || r.finalDecision === 'INCONCLUSIVE').length,
    classification: qaClassification,
  };

  const benchmarkReport: BenchmarkDatasetReport = {
    totalLabeledTrials: benchmarkEval.length,
    operationalLabeledTrials: benchmarkEval.length,
    syntheticLabeledTrials: labeledQa.length,
    duplicateExcludedCount,
    subjectOverlapDetected,
    insufficientData: classification.insufficientData || subjectOverlapDetected,
    insufficientDataMessage:
      classification.insufficientData || subjectOverlapDetected
        ? 'Real-world biometric accuracy has not yet been established.'
        : 'Statistically grounded subject-disjoint benchmark sample.',
    classification,
    operationalOnlyClassification: opOnlyClassification,
  };

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
    for (const r of benchmarkEval) {
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
      metrics: modTrials.length > 0 && !subjectOverlapDetected ? computeClassificationMetrics(modTrials, thr) : null,
    };
  };

  const failCounts = new Map<string, number>();
  for (const r of records) {
    if (r.outcome === 'no_match' || r.outcome === 'not_evaluated' || r.finalDecision === 'INCONCLUSIVE') {
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
    labeledAttempts: benchmarkEval.length,
    unlabeledAttempts: unlabeled.length,
    successfulVerifications: successful,
    rejectedVerifications: rejected,
    notEvaluatedVerifications: notEvaluated,
    inconclusiveRate,
    captureFailureCount,
    captureFailureRate,
    operationalVerificationSuccessRate,
    livenessKnownCount: liveKnownCount,
    livenessSuccessRate,
    livenessFailureRate,
    livenessBreakdown: {
      passed: livePassed,
      failed: liveFailed,
      inconclusive: liveInconclusive,
      notSupported: liveNotSupported,
    },
    sampleQualityDistribution,
    conflictCount: records.filter((r) => r.conflictDetected === true).length,
    avgRiskScore,
    latency,
    dateRange,
    datasets: {
      operational: operationalReport,
      syntheticQa: syntheticQaReport,
      benchmark: benchmarkReport,
    },
    classification,
    perModality: {
      face: buildModSummary('face'),
      voice: buildModSummary('voice'),
      fingerprint: buildModSummary('fingerprint'),
      multimodal: buildModSummary('multimodal'),
    },
    failedBreakdown,
    methodologyNote:
      'Operational Data, Synthetic QA Data, and Benchmark Evaluation Data are tracked strictly separately. Classification Accuracy, TAR/GAR, FAR/IAR, FRR, Precision, Recall, F1, EER, and Wilson 95% CIs exclude synthetic QA probes and unlabeled operational attempts, deduplicate repeated sample hashes, and display "Real-world biometric accuracy has not yet been established." until a subject-disjoint benchmark (>=3 genuine, >=3 impostor) exists.',
  };
}

