export interface ChallengeStateLike {
  challengeToken?: string | null;
  faceChallenge?: string | null;
  voicePassphrase?: string | null;
  expiresAt?: number | null;
  consumed?: boolean;
}

export interface ChallengeUsabilityResult {
  valid: boolean;
  reason?: 'missing' | 'consumed' | 'expired' | 'expiring_soon';
}

export function isChallengeUsable(
  challenge: ChallengeStateLike | null | undefined,
  now = Date.now(),
  minRemainingMs = 5000
): ChallengeUsabilityResult {
  if (!challenge || typeof challenge.challengeToken !== 'string' || challenge.challengeToken.trim().length === 0) {
    return { valid: false, reason: 'missing' };
  }
  if (challenge.consumed === true) {
    return { valid: false, reason: 'consumed' };
  }
  if (typeof challenge.expiresAt === 'number' && Number.isFinite(challenge.expiresAt)) {
    const remaining = challenge.expiresAt - now;
    if (remaining <= 0) {
      return { valid: false, reason: 'expired' };
    }
    if (minRemainingMs > 0 && remaining < minRemainingMs) {
      return { valid: false, reason: 'expiring_soon' };
    }
  }
  return { valid: true };
}

export function shouldBlockCaptureOnChallengeFailure(strictLiveness: boolean | undefined): boolean {
  return strictLiveness !== false;
}

function summarizeVectorDigest(vec: unknown): string {
  if (!Array.isArray(vec) || vec.length === 0) return 'none';
  const len = vec.length;
  const indices = [0, Math.floor(len / 3), Math.floor((2 * len) / 3), len - 1];
  const picks = indices.map((idx) => {
    const v = Number(vec[idx]);
    return Number.isFinite(v) ? v.toFixed(5) : 'nan';
  });
  return `${len}:${picks.join(',')}`;
}

function summarizeFingerprintDigest(tpl: unknown): string {
  if (!tpl || typeof tpl !== 'object') return 'none';
  const minutiae = (tpl as { minutiae?: unknown[] }).minutiae;
  if (!Array.isArray(minutiae) || minutiae.length === 0) return 'fp:0';
  const first = minutiae[0] as { x?: unknown; y?: unknown; theta?: unknown } | undefined;
  const last = minutiae[minutiae.length - 1] as { x?: unknown; y?: unknown; theta?: unknown } | undefined;
  const fmt = (m?: { x?: unknown; y?: unknown; theta?: unknown }) =>
    `${Number(m?.x ?? 0).toFixed(2)},${Number(m?.y ?? 0).toFixed(2)},${Number(m?.theta ?? 0).toFixed(2)}`;
  return `fp:${minutiae.length}:${fmt(first)}:${fmt(last)}`;
}

export interface AttemptSignatureInput {
  identityRef: string;
  pipeline: string;
  fusionPolicy: string;
  adaptiveEnabled: boolean;
  groundTruth: string;
  isTestProbe: boolean;
  subjectKey?: string;
  benchmarkBatchId?: string;
  faceVec?: unknown;
  faceCaptureSource?: string;
  voiceVec?: unknown;
  voiceCaptureSource?: string;
  fpTemplate?: unknown;
  fpCaptureSource?: string;
}

export function computeVerificationAttemptSignature(input: AttemptSignatureInput): string {
  return [
    String(input.identityRef || '').trim(),
    String(input.pipeline || '').trim(),
    String(input.fusionPolicy || '').trim(),
    input.adaptiveEnabled ? 'ad1' : 'ad0',
    String(input.groundTruth || 'unlabeled'),
    input.isTestProbe ? 'qa1' : 'qa0',
    String(input.subjectKey || '').trim(),
    String(input.benchmarkBatchId || '').trim(),
    `f[${input.faceCaptureSource || 'none'}|${summarizeVectorDigest(input.faceVec)}]`,
    `v[${input.voiceCaptureSource || 'none'}|${summarizeVectorDigest(input.voiceVec)}]`,
    `p[${input.fpCaptureSource || 'none'}|${summarizeFingerprintDigest(input.fpTemplate)}]`,
  ].join('|');
}

export interface PendingVerificationAttempt<TResult = unknown> {
  attemptKey: string;
  verificationId: string;
  apiResult: TResult | null;
  persisted: boolean;
}

export type VerificationAttemptPlan<TResult = unknown> =
  | { action: 'already_persisted'; verificationId: string; apiResult: TResult | null }
  | { action: 'retry_persistence_only'; verificationId: string; apiResult: TResult }
  | { action: 'run_full'; verificationId: string };

export function resolveVerificationAttemptPlan<TResult>(
  existing: PendingVerificationAttempt<TResult> | null | undefined,
  currentAttemptKey: string,
  createVerificationId: () => string
): VerificationAttemptPlan<TResult> {
  if (existing && existing.attemptKey === currentAttemptKey) {
    if (existing.persisted) {
      return {
        action: 'already_persisted',
        verificationId: existing.verificationId,
        apiResult: existing.apiResult,
      };
    }
    if (existing.apiResult !== null && existing.apiResult !== undefined) {
      return {
        action: 'retry_persistence_only',
        verificationId: existing.verificationId,
        apiResult: existing.apiResult,
      };
    }
    return {
      action: 'run_full',
      verificationId: existing.verificationId,
    };
  }
  return {
    action: 'run_full',
    verificationId: createVerificationId(),
  };
}
