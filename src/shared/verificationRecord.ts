export const VALID_IDENTITY_REF_RE = /^[a-zA-Z0-9_-]{2,64}$/;
export const VALID_FIRESTORE_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;

export const VERIFICATION_SUPPORTED_MODALITIES = ['face', 'voice', 'fingerprint'] as const;
export type VerificationModality = (typeof VERIFICATION_SUPPORTED_MODALITIES)[number];

export const VERIFICATION_RECORD_ALLOWED_KEYS = [
  'verificationId',
  'identityRef',
  'modalities',
  'pipeline',
  'outcome',
  'finalDecision',
  'policyDecision',
  'reasonCode',
  'score',
  'riskScore',
  'riskLevel',
  'livenessPassed',
  'livenessStatus',
  'livenessDecision',
  'livenessScore',
  'challengeVerified',
  'adaptiveApplied',
  'groundTruth',
  'datasetCategory',
  'isTestProbe',
  'captureFailure',
  'processingTimeMs',
  'confidence',
  'identityConfidence',
  'sampleQualityScore',
  'livenessConfidence',
  'confidenceBand',
  'conflictDetected',
  'featureVersion',
  'faceScore',
  'voiceScore',
  'fingerprintScore',
  'faceQuality',
  'voiceQuality',
  'fingerprintQuality',
  'faceStatus',
  'voiceStatus',
  'fingerprintStatus',
  'matchedMinutiae',
  'probeMinutiae',
  'subjectKey',
  'partition',
  'sampleHash',
  'benchmarkBatchId',
  'provenanceSignature',
  'operatorUid',
  'createdAt',
] as const;

export const VERIFICATION_RECORD_REQUIRED_KEYS = [
  'verificationId',
  'identityRef',
  'modalities',
  'outcome',
  'policyDecision',
  'reasonCode',
  'operatorUid',
  'createdAt',
] as const;

const ALLOWED_KEYS_SET = new Set<string>(VERIFICATION_RECORD_ALLOWED_KEYS);
const MODALITY_SET = new Set<string>(VERIFICATION_SUPPORTED_MODALITIES);

export interface ModalityEvaluationInput {
  score?: number;
  qualityScore?: number;
  status?: string;
  details?: {
    matchedMinutiae?: number;
    probeMinutiae?: number;
  };
}

export interface BuildVerificationRecordInput {
  uid: string;
  verificationId: string;
  identityRef: string;
  modalities: unknown;
  pipeline?: string;
  outcome: string;
  finalDecision?: string;
  livenessStatus?: string;
  livenessDecision?: string;
  challengeVerified?: boolean;
  datasetCategory?: string;
  captureFailure?: boolean;
  reasonCode?: string;
  score?: number;
  confidence?: number;
  identityConfidence?: number;
  sampleQualityScore?: number;
  livenessConfidence?: number;
  confidenceBand?: string;
  conflictDetected?: boolean;
  processingTimeMs?: number;
  featureVersion?: string;
  groundTruth?: string;
  isTestProbe?: boolean;
  modalityEvaluations?: Record<string, ModalityEvaluationInput | undefined>;
  riskScore?: number;
  riskLevel?: string;
  livenessPassed?: boolean;
  livenessScore?: number;
  adaptiveApplied?: boolean;
  subjectKey?: string;
  partition?: string;
  sampleHash?: string;
  benchmarkBatchId?: string;
  provenanceSignature?: string;
  createdAt: unknown;
}

function finiteClamp(value: unknown, min: number, max: number, digits = 3): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Number(Math.min(max, Math.max(min, value)).toFixed(digits));
}

export function buildVerificationRecordPayload(input: BuildVerificationRecordInput): Record<string, unknown> {
  const uid = String(input.uid || '').trim();
  if (!VALID_FIRESTORE_ID_RE.test(uid)) {
    throw new Error('Invalid authenticated operator UID.');
  }

  const verificationId = String(input.verificationId || '').trim();
  if (!VALID_FIRESTORE_ID_RE.test(verificationId)) {
    throw new Error('Invalid verificationId.');
  }

  const cleanIdentityRef = String(input.identityRef || '').trim();
  if (!VALID_IDENTITY_REF_RE.test(cleanIdentityRef)) {
    throw new Error('Invalid identity reference (must be 2-64 alphanumeric, underscore, or hyphen characters).');
  }

  const safeModalities = Array.isArray(input.modalities)
    ? [...new Set(input.modalities.filter((item): item is string => typeof item === 'string' && MODALITY_SET.has(item)))].slice(0, 3)
    : [];
  if (safeModalities.length === 0) {
    throw new Error('At least one supported modality (face, voice, or fingerprint) is required.');
  }

  if (!['match', 'no_match', 'not_evaluated'].includes(input.outcome)) {
    throw new Error(`Invalid verification outcome "${String(input.outcome)}".`);
  }

  const safeGroundTruth = ['genuine', 'impostor', 'unlabeled'].includes(String(input.groundTruth))
    ? String(input.groundTruth)
    : 'unlabeled';
  const derivedDatasetCategory = ['operational', 'synthetic_qa', 'benchmark_eval'].includes(String(input.datasetCategory))
    ? String(input.datasetCategory)
    : input.isTestProbe
    ? 'synthetic_qa'
    : 'operational';

  const safeScore = finiteClamp(input.score, 0, 1, 4);
  const cleanPipeline = String(input.pipeline || 'hierarchical').trim().slice(0, 64) || 'hierarchical';
  const cleanReasonCode = String(input.reasonCode || 'evaluated').trim().slice(0, 80) || 'evaluated';

  const docData: Record<string, unknown> = {
    verificationId,
    identityRef: cleanIdentityRef,
    modalities: safeModalities,
    pipeline: cleanPipeline,
    outcome: input.outcome,
    policyDecision: 'pending',
    reasonCode: cleanReasonCode,
    score: safeScore ?? 0,
    operatorUid: uid,
    datasetCategory: derivedDatasetCategory,
    captureFailure: Boolean(input.captureFailure),
    groundTruth: safeGroundTruth,
    createdAt: input.createdAt,
  };

  if (input.finalDecision && ['VERIFIED', 'REJECTED', 'INCONCLUSIVE'].includes(input.finalDecision)) {
    docData.finalDecision = input.finalDecision;
  }
  if (
    input.livenessStatus &&
    ['LIVENESS PASSED', 'LIVENESS FAILED', 'INCONCLUSIVE', 'NOT SUPPORTED'].includes(input.livenessStatus)
  ) {
    docData.livenessStatus = input.livenessStatus;
  }
  if (input.livenessDecision && ['PASSED', 'FAILED', 'INCONCLUSIVE'].includes(input.livenessDecision)) {
    docData.livenessDecision = input.livenessDecision;
  }
  if (typeof input.challengeVerified === 'boolean') {
    docData.challengeVerified = input.challengeVerified;
  }
  {
    const value = finiteClamp(input.riskScore, 0, 100, 0);
    if (value !== null) docData.riskScore = value;
  }
  if (input.riskLevel && ['low', 'medium', 'high', 'critical'].includes(input.riskLevel)) {
    docData.riskLevel = input.riskLevel;
  }
  if (typeof input.livenessPassed === 'boolean') {
    docData.livenessPassed = input.livenessPassed;
  }
  {
    const value = finiteClamp(input.livenessScore, 0, 1, 2);
    if (value !== null) docData.livenessScore = value;
  }
  if (typeof input.adaptiveApplied === 'boolean') {
    docData.adaptiveApplied = input.adaptiveApplied;
  }
  if (typeof input.isTestProbe === 'boolean') {
    docData.isTestProbe = input.isTestProbe;
  }
  {
    const value = finiteClamp(input.processingTimeMs, 0, 120000, 1);
    if (value !== null) docData.processingTimeMs = value;
  }
  {
    const value = finiteClamp(input.confidence, 0, 1, 3);
    if (value !== null) docData.confidence = value;
  }
  {
    const value = finiteClamp(input.identityConfidence, 0, 1, 3);
    if (value !== null) docData.identityConfidence = value;
  }
  {
    const value = finiteClamp(input.sampleQualityScore, 0, 1, 3);
    if (value !== null) docData.sampleQualityScore = value;
  }
  {
    const value = finiteClamp(input.livenessConfidence, 0, 1, 3);
    if (value !== null) docData.livenessConfidence = value;
  }
  if (input.confidenceBand && ['high', 'moderate', 'low'].includes(input.confidenceBand)) {
    docData.confidenceBand = input.confidenceBand;
  }
  if (typeof input.conflictDetected === 'boolean') {
    docData.conflictDetected = input.conflictDetected;
  }
  if (typeof input.featureVersion === 'string' && input.featureVersion.trim().length > 0) {
    docData.featureVersion = input.featureVersion.trim().slice(0, 32);
  }
  if (typeof input.subjectKey === 'string' && input.subjectKey.trim().length > 0) {
    docData.subjectKey = input.subjectKey.trim().slice(0, 80);
  }
  if (input.partition === 'eval' || input.partition === 'unassigned') {
    docData.partition = input.partition;
  }
  if (typeof input.sampleHash === 'string' && input.sampleHash.trim().length > 0) {
    docData.sampleHash = input.sampleHash.trim().slice(0, 128);
  }
  if (typeof input.benchmarkBatchId === 'string' && input.benchmarkBatchId.trim().length > 0) {
    docData.benchmarkBatchId = input.benchmarkBatchId.trim().slice(0, 80);
  }
  if (typeof input.provenanceSignature === 'string' && input.provenanceSignature.trim().length > 0) {
    docData.provenanceSignature = input.provenanceSignature.trim().slice(0, 160);
  }

  const modEvals = input.modalityEvaluations;
  if (modEvals?.face) {
    const sc = finiteClamp(modEvals.face.score, 0, 1, 4);
    if (sc !== null) docData.faceScore = sc;
    const q = finiteClamp(modEvals.face.qualityScore, 0, 100, 0);
    if (q !== null) docData.faceQuality = q;
    if (modEvals.face.status && ['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(modEvals.face.status)) {
      docData.faceStatus = modEvals.face.status;
    }
  }
  if (modEvals?.voice) {
    const sc = finiteClamp(modEvals.voice.score, 0, 1, 4);
    if (sc !== null) docData.voiceScore = sc;
    const q = finiteClamp(modEvals.voice.qualityScore, 0, 100, 0);
    if (q !== null) docData.voiceQuality = q;
    if (modEvals.voice.status && ['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(modEvals.voice.status)) {
      docData.voiceStatus = modEvals.voice.status;
    }
  }
  if (modEvals?.fingerprint) {
    const sc = finiteClamp(modEvals.fingerprint.score, 0, 1, 4);
    if (sc !== null) docData.fingerprintScore = sc;
    const q = finiteClamp(modEvals.fingerprint.qualityScore, 0, 100, 0);
    if (q !== null) docData.fingerprintQuality = q;
    if (
      modEvals.fingerprint.status &&
      ['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(modEvals.fingerprint.status)
    ) {
      docData.fingerprintStatus = modEvals.fingerprint.status;
    }
    const fpDet = modEvals.fingerprint.details || {};
    if (typeof fpDet.matchedMinutiae === 'number' && Number.isFinite(fpDet.matchedMinutiae)) {
      docData.matchedMinutiae = Math.max(0, Math.min(500, Math.round(fpDet.matchedMinutiae)));
    }
    if (typeof fpDet.probeMinutiae === 'number' && Number.isFinite(fpDet.probeMinutiae)) {
      docData.probeMinutiae = Math.max(0, Math.min(500, Math.round(fpDet.probeMinutiae)));
    }
  }

  return docData;
}

/**
 * Mirrors `isValidVerificationRecord(data)` in `firestore.rules` so unit tests and
 * pre-write defensive checks fail fast if any field violates schema/allowlist rules.
 */
export function validateVerificationRecordDoc(
  data: Record<string, unknown>,
  expectedUid: string,
  expectedVerificationId: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const keys = Object.keys(data);

  for (const reqKey of VERIFICATION_RECORD_REQUIRED_KEYS) {
    if (!(reqKey in data) || data[reqKey] === undefined) {
      errors.push(`Missing required key "${reqKey}".`);
    }
  }
  for (const key of keys) {
    if (!ALLOWED_KEYS_SET.has(key)) {
      errors.push(`Unexpected key "${key}" not allowed by firestore.rules.`);
    }
    if (data[key] === undefined) {
      errors.push(`Key "${key}" must not be undefined.`);
    }
  }

  if (typeof data.verificationId !== 'string' || !VALID_FIRESTORE_ID_RE.test(data.verificationId)) {
    errors.push('Invalid verificationId format.');
  } else if (data.verificationId !== expectedVerificationId) {
    errors.push('verificationId does not match document ID.');
  }

  if (typeof data.identityRef !== 'string' || !VALID_IDENTITY_REF_RE.test(data.identityRef)) {
    errors.push('Invalid identityRef.');
  }

  if (
    !Array.isArray(data.modalities) ||
    data.modalities.length < 1 ||
    data.modalities.length > 3 ||
    typeof data.modalities[0] !== 'string' ||
    data.modalities.some((m) => typeof m !== 'string' || !MODALITY_SET.has(m))
  ) {
    errors.push('Invalid modalities array.');
  }

  if ('pipeline' in data && (typeof data.pipeline !== 'string' || data.pipeline.length < 1 || data.pipeline.length > 64)) {
    errors.push('Invalid pipeline string.');
  }
  if (!['match', 'no_match', 'not_evaluated'].includes(String(data.outcome))) {
    errors.push('Invalid outcome.');
  }
  if ('finalDecision' in data && !['VERIFIED', 'REJECTED', 'INCONCLUSIVE'].includes(String(data.finalDecision))) {
    errors.push('Invalid finalDecision.');
  }
  if (data.policyDecision !== 'pending') {
    errors.push('policyDecision must equal "pending".');
  }
  if (typeof data.reasonCode !== 'string' || data.reasonCode.length < 1 || data.reasonCode.length > 80) {
    errors.push('Invalid reasonCode.');
  }

  const checkNum = (field: string, min: number, max?: number) => {
    if (!(field in data)) return;
    const v = data[field];
    if (typeof v !== 'number' || !Number.isFinite(v) || v < min || (max !== undefined && v > max)) {
      errors.push(`Invalid numeric range for ${field}: ${String(v)}.`);
    }
  };
  checkNum('score', 0, 1);
  checkNum('riskScore', 0, 100);
  checkNum('livenessScore', 0, 1);
  checkNum('processingTimeMs', 0, 120000);
  checkNum('confidence', 0, 1);
  checkNum('identityConfidence', 0, 1);
  checkNum('sampleQualityScore', 0, 1);
  checkNum('livenessConfidence', 0, 1);
  checkNum('faceScore', 0, 1);
  checkNum('voiceScore', 0, 1);
  checkNum('fingerprintScore', 0, 1);
  checkNum('faceQuality', 0, 100);
  checkNum('voiceQuality', 0, 100);
  checkNum('fingerprintQuality', 0, 100);
  checkNum('matchedMinutiae', 0);
  checkNum('probeMinutiae', 0);

  if ('riskLevel' in data && !['low', 'medium', 'high', 'critical'].includes(String(data.riskLevel))) {
    errors.push('Invalid riskLevel.');
  }
  if (
    'livenessStatus' in data &&
    !['LIVENESS PASSED', 'LIVENESS FAILED', 'INCONCLUSIVE', 'NOT SUPPORTED'].includes(String(data.livenessStatus))
  ) {
    errors.push('Invalid livenessStatus.');
  }
  if ('livenessDecision' in data && !['PASSED', 'FAILED', 'INCONCLUSIVE'].includes(String(data.livenessDecision))) {
    errors.push('Invalid livenessDecision.');
  }
  if ('groundTruth' in data && !['genuine', 'impostor', 'unlabeled'].includes(String(data.groundTruth))) {
    errors.push('Invalid groundTruth.');
  }
  if ('datasetCategory' in data && !['operational', 'synthetic_qa', 'benchmark_eval'].includes(String(data.datasetCategory))) {
    errors.push('Invalid datasetCategory.');
  }
  if ('confidenceBand' in data && !['high', 'moderate', 'low'].includes(String(data.confidenceBand))) {
    errors.push('Invalid confidenceBand.');
  }
  for (const modField of ['faceStatus', 'voiceStatus', 'fingerprintStatus'] as const) {
    if (
      modField in data &&
      !['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(String(data[modField]))
    ) {
      errors.push(`Invalid ${modField}.`);
    }
  }
  if ('partition' in data && data.partition !== 'eval' && data.partition !== 'unassigned') {
    errors.push('Invalid partition.');
  }

  for (const boolField of [
    'livenessPassed',
    'challengeVerified',
    'adaptiveApplied',
    'isTestProbe',
    'captureFailure',
    'conflictDetected',
  ] as const) {
    if (boolField in data && typeof data[boolField] !== 'boolean') {
      errors.push(`Field ${boolField} must be boolean.`);
    }
  }

  const checkStr = (field: string, maxLen: number) => {
    if (!(field in data)) return;
    const v = data[field];
    if (typeof v !== 'string' || v.length < 1 || v.length > maxLen) {
      errors.push(`Invalid string ${field} length.`);
    }
  };
  checkStr('featureVersion', 32);
  checkStr('subjectKey', 80);
  checkStr('sampleHash', 128);
  checkStr('benchmarkBatchId', 80);
  checkStr('provenanceSignature', 160);

  if (data.operatorUid !== expectedUid) {
    errors.push('operatorUid must equal authenticated UID.');
  }
  if (!data.createdAt) {
    errors.push('createdAt server timestamp sentinel is required.');
  }

  return { valid: errors.length === 0, errors };
}
