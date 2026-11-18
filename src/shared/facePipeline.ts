import { l2Normalize } from './voiceDsp.ts';

export const FACE_EMBEDDING_DIM = 1024;
export const MIN_FACE_LANDMARKS_MESH = 68;

export type FaceLogLevel = 'silent' | 'error' | 'warn' | 'info' | 'debug';

export interface FaceDiagnosticEvent {
  ts: string;
  level: Exclude<FaceLogLevel, 'silent'>;
  stage: string;
  message: string;
  meta?: Record<string, unknown>;
}

const LOG_PRIORITY: Record<FaceLogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

const SENSITIVE_META_KEYS = new Set([
  'vector',
  'embedding',
  'descriptor',
  'template',
  'pixels',
  'imagedata',
  'dataurl',
  'canvas',
  'rawimage',
]);

export interface FaceDiagnosticsConfig {
  level: FaceLogLevel;
  sink?: (event: FaceDiagnosticEvent) => void;
}

const diagState: FaceDiagnosticsConfig = {
  level: 'warn',
  sink: undefined,
};

export function setFaceDiagnosticsConfig(cfg: Partial<FaceDiagnosticsConfig>): FaceDiagnosticsConfig {
  if (cfg.level && cfg.level in LOG_PRIORITY) {
    diagState.level = cfg.level;
  }
  if ('sink' in cfg) {
    diagState.sink = cfg.sink;
  }
  return { ...diagState };
}

export function getFaceDiagnosticsConfig(): FaceDiagnosticsConfig {
  return { ...diagState };
}

export function sanitizeTelemetryMeta(meta: unknown, depth = 0): Record<string, unknown> | undefined {
  if (!meta || typeof meta !== 'object') return undefined;
  if (depth > 3) return undefined;
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(meta as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    if (
      SENSITIVE_META_KEYS.has(lower) ||
      lower.includes('embedding') ||
      lower.includes('descriptor') ||
      lower.includes('vector') ||
      lower.includes('pixel')
    ) {
      out[key] = '[REDACTED]';
      continue;
    }
    if (
      val === null ||
      typeof val === 'string' ||
      typeof val === 'number' ||
      typeof val === 'boolean'
    ) {
      out[key] = val;
    } else if (Array.isArray(val)) {
      if (val.length > 16) {
        out[key] = `[Array(${val.length})]`;
      } else {
        out[key] = val.map((item) =>
          typeof item === 'object' && item !== null ? sanitizeTelemetryMeta(item, depth + 1) ?? '[Object]' : item
        );
      }
    } else if (typeof val === 'object') {
      out[key] = sanitizeTelemetryMeta(val, depth + 1) ?? '[Object]';
    }
  }
  return out;
}

export function logFaceDiagnostic(
  level: Exclude<FaceLogLevel, 'silent'>,
  stage: string,
  message: string,
  meta?: Record<string, unknown>
): FaceDiagnosticEvent | null {
  if (LOG_PRIORITY[level] > LOG_PRIORITY[diagState.level]) return null;
  const event: FaceDiagnosticEvent = {
    ts: new Date().toISOString(),
    level,
    stage,
    message,
    ...(meta ? { meta: sanitizeTelemetryMeta(meta) } : {}),
  };
  if (diagState.sink) {
    diagState.sink(event);
  } else if (typeof console !== 'undefined') {
    const fn =
      level === 'error'
        ? console.error
        : level === 'warn'
        ? console.warn
        : level === 'info'
        ? console.info
        : console.debug;
    if (typeof fn === 'function') {
      fn(`[BioGuard FaceEngine:${stage}] ${message}`, event.meta || '');
    }
  }
  return event;
}

export interface CodedFaceError extends Error {
  code: string;
  feedbackLabel: string;
  recoverable?: boolean;
  details?: Record<string, unknown>;
}

export function createFaceError(
  code: string,
  feedbackLabel: string,
  message: string,
  opts: { recoverable?: boolean; details?: Record<string, unknown>; cause?: unknown } = {}
): CodedFaceError {
  const err = new Error(message, opts.cause ? { cause: opts.cause } : undefined) as CodedFaceError;
  err.code = code;
  err.feedbackLabel = feedbackLabel;
  err.recoverable = opts.recoverable ?? true;
  if (opts.details) {
    err.details = sanitizeTelemetryMeta(opts.details);
  }
  return err;
}

export interface MutexQueue {
  tail: Promise<unknown>;
  pendingCount: number;
}

export function createMutexQueue(): MutexQueue {
  return { tail: Promise.resolve(), pendingCount: 0 };
}

export function runSerialized<T>(queue: MutexQueue, task: () => Promise<T>): Promise<T> {
  queue.pendingCount += 1;
  const run = async (): Promise<T> => {
    try {
      return await task();
    } finally {
      queue.pendingCount = Math.max(0, queue.pendingCount - 1);
    }
  };
  const next = queue.tail.then(run, run);
  queue.tail = next.catch(() => undefined);
  return next;
}

export interface LandmarkValidationResult {
  landmarkCount: number;
  detectionConfidence: number;
  noseXNorm?: number;
}

export function validateFaceLandmarks(
  face: {
    mesh?: unknown;
    box?: unknown;
    boxRaw?: unknown;
    faceScore?: number;
    boxScore?: number;
    score?: number;
  } | null | undefined,
  imgWidth = 640
): LandmarkValidationResult {
  if (!face || typeof face !== 'object') {
    throw createFaceError(
      'no_face_detected',
      'Face Not Detected',
      'Face Not Detected: No valid face region was returned by the detector.'
    );
  }

  const mesh = face.mesh;
  if (!Array.isArray(mesh) || mesh.length < MIN_FACE_LANDMARKS_MESH) {
    throw createFaceError(
      'landmark_detection_failed',
      'Landmark Detection Failure',
      `Landmark Detection Failure: Facial landmark mesh incomplete (detected=${Array.isArray(mesh) ? mesh.length : 0}, minimum=${MIN_FACE_LANDMARKS_MESH}). Center face in even lighting.`,
      {
        details: {
          meshCount: Array.isArray(mesh) ? mesh.length : 0,
          boxScore: typeof face.boxScore === 'number' ? face.boxScore : null,
          faceScore: typeof face.faceScore === 'number' ? face.faceScore : null,
        },
      }
    );
  }

  // Verify representative landmarks (nose tip & eye/face boundary indices) have finite numeric coordinates
  const probeIndices = [1, 10, 33, 133, 152, 234, 263, 362, 454].filter((i) => i < mesh.length);
  for (const idx of probeIndices) {
    const pt = mesh[idx];
    if (!Array.isArray(pt) || typeof pt[0] !== 'number' || typeof pt[1] !== 'number' || !Number.isFinite(pt[0]) || !Number.isFinite(pt[1])) {
      throw createFaceError(
        'landmark_detection_failed',
        'Landmark Detection Failure',
        'Landmark Detection Failure: Facial landmark coordinates are invalid or non-finite.',
        { details: { invalidIndex: idx, meshCount: mesh.length } }
      );
    }
  }

  const box = face.box;
  if (!Array.isArray(box) || box.length < 4 || box.some((n) => typeof n !== 'number' || !Number.isFinite(n))) {
    throw createFaceError(
      'landmark_detection_failed',
      'Landmark Detection Failure',
      'Landmark Detection Failure: Face bounding box coordinates are missing or invalid.'
    );
  }

  const rawConf =
    typeof face.faceScore === 'number' && Number.isFinite(face.faceScore) && face.faceScore > 0
      ? face.faceScore
      : typeof face.boxScore === 'number' && Number.isFinite(face.boxScore) && face.boxScore > 0
      ? face.boxScore
      : typeof face.score === 'number' && Number.isFinite(face.score)
      ? face.score
      : 0;

  const rawNoseX = Array.isArray(mesh[1]) ? mesh[1][0] : undefined;
  const noseXNorm =
    typeof rawNoseX === 'number' && Number.isFinite(rawNoseX) && imgWidth > 0
      ? Number(Math.max(0, Math.min(1, rawNoseX / imgWidth)).toFixed(4))
      : undefined;

  return {
    landmarkCount: mesh.length,
    detectionConfidence: Number(Math.max(0, Math.min(1, rawConf)).toFixed(3)),
    ...(noseXNorm !== undefined ? { noseXNorm } : {}),
  };
}

export function validateFaceEmbedding(
  rawEmbedding: unknown,
  expectedDim = FACE_EMBEDDING_DIM,
  context: { descriptionEnabled?: boolean; backend?: string } = {}
): { vector: number[]; dim: number; rawNorm: number; std: number } {
  const isArrayLike =
    Array.isArray(rawEmbedding) ||
    ArrayBuffer.isView(rawEmbedding);
  const length = isArrayLike ? (rawEmbedding as ArrayLike<unknown>).length : 0;

  if (!isArrayLike || length === 0) {
    const reason =
      context.descriptionEnabled === false
        ? 'Face description model was disabled during detection.'
        : 'Face recognition descriptor model returned an empty embedding.';
    throw createFaceError(
      'embedding_model_inference_failed',
      'Model Inference Failure',
      `Embedding Model Inference Failure: ${reason}`,
      {
        details: {
          receivedLength: length,
          expectedDim,
          descriptionEnabled: context.descriptionEnabled ?? null,
          backend: context.backend ?? null,
        },
      }
    );
  }

  if (length !== expectedDim) {
    throw createFaceError(
      'invalid_embedding_dimension',
      'Model Inference Failure',
      `Embedding Model Inference Failure: Unexpected embedding length ${length} (expected ${expectedDim}).`,
      { details: { receivedLength: length, expectedDim, backend: context.backend ?? null } }
    );
  }

  const values = new Array<number>(expectedDim);
  let sum = 0;
  let sqSum = 0;
  for (let i = 0; i < expectedDim; i++) {
    const v = Number((rawEmbedding as ArrayLike<unknown>)[i]);
    if (!Number.isFinite(v)) {
      throw createFaceError(
        'invalid_embedding_nan',
        'Model Inference Failure',
        'Embedding Model Inference Failure: Model output contained NaN/Infinity values (WebGL numerical instability).',
        { details: { invalidAtIndex: i, backend: context.backend ?? null } }
      );
    }
    values[i] = v;
    sum += v;
    sqSum += v * v;
  }

  const rawNorm = Math.sqrt(sqSum);
  const mean = sum / expectedDim;
  const variance = Math.max(0, sqSum / expectedDim - mean * mean);
  const std = Math.sqrt(variance);

  if (rawNorm < 1e-6 || std < 1e-5) {
    throw createFaceError(
      'degenerate_embedding_vector',
      'Model Inference Failure',
      'Embedding Model Inference Failure: Generated embedding vector is zero or degenerate.',
      { details: { rawNorm: Number(rawNorm.toExponential(2)), std: Number(std.toExponential(2)) } }
    );
  }

  return {
    vector: l2Normalize(values),
    dim: expectedDim,
    rawNorm: Number(rawNorm.toFixed(4)),
    std: Number(std.toFixed(5)),
  };
}

export interface FaceRoiQualityMetrics {
  meanBrightness: number;
  contrastStd: number;
  sharpness: number;
  faceWidthPx: number;
  faceHeightPx: number;
}

export interface FacePoseAngles {
  yawDeg: number;
  pitchDeg: number;
  rollDeg: number;
}

export interface FaceQualityEvaluation {
  faceQualityScore: number;
  spoofRiskFlag: boolean;
  feedbackLabel: string;
}

export function evaluateFacePoseAndQuality(params: {
  pose: FacePoseAngles;
  roiQ: FaceRoiQualityMetrics;
  detectionConfidence: number;
  antispoofScore: number | null;
  livenessNetScore: number | null;
  isLiveCapture?: boolean;
}): FaceQualityEvaluation {
  const { pose, roiQ, detectionConfidence, antispoofScore, isLiveCapture } = params;

  if (Math.abs(pose.yawDeg) > 36 || Math.abs(pose.pitchDeg) > 32) {
    throw createFaceError(
      'extreme_face_pose',
      'Pose Off-Center',
      `Pose Off-Center: Head angle too extreme (yaw ${pose.yawDeg}°, pitch ${pose.pitchDeg}°). Look directly at the camera.`,
      { details: { yawDeg: pose.yawDeg, pitchDeg: pose.pitchDeg } }
    );
  }

  if (roiQ.faceWidthPx < 44 || roiQ.faceHeightPx < 44) {
    throw createFaceError(
      'low_face_resolution',
      'Face Too Far',
      `Face Too Far: Detected face region is too small (${roiQ.faceWidthPx}×${roiQ.faceHeightPx}px). Move closer to the camera.`,
      { details: { faceWidthPx: roiQ.faceWidthPx, faceHeightPx: roiQ.faceHeightPx } }
    );
  }

  if (roiQ.meanBrightness < 24 || roiQ.meanBrightness > 240) {
    throw createFaceError(
      'poor_illumination',
      'Poor Lighting',
      `Poor Lighting: ${roiQ.meanBrightness < 24 ? 'Frame too dark' : 'Frame overexposed'} (brightness ${roiQ.meanBrightness}/255). Use even front lighting.`,
      { details: { meanBrightness: roiQ.meanBrightness, contrastStd: roiQ.contrastStd } }
    );
  }

  // Calibrated contrast/sharpness gates distinguishing genuine blur/flat texture from soft mobile webcam feeds
  const minSharpness = isLiveCapture ? 2.6 : 2.8;
  const minContrast = 6.5;
  if (roiQ.contrastStd < minContrast) {
    throw createFaceError(
      'blurry_face_roi',
      'Poor Lighting',
      `Poor Lighting: Face contrast too low (${roiQ.contrastStd}). Improve front lighting and avoid glare.`,
      { details: { contrastStd: roiQ.contrastStd, sharpness: roiQ.sharpness } }
    );
  }
  if (roiQ.sharpness < minSharpness) {
    throw createFaceError(
      'blurry_face_roi',
      'Motion Blur',
      `Motion Blur: Face crop sharpness too low (${roiQ.sharpness} < ${minSharpness}). Hold steady briefly during capture.`,
      { details: { sharpness: roiQ.sharpness, contrastStd: roiQ.contrastStd } }
    );
  }

  const posePenalty = (Math.abs(pose.yawDeg) + Math.abs(pose.pitchDeg) + Math.abs(pose.rollDeg)) * 0.45;
  const faceQualityScore = Math.max(
    15,
    Math.min(
      100,
      Math.round(
        detectionConfidence * 45 +
          Math.min(1, roiQ.sharpness / 16) * 25 +
          Math.min(1, roiQ.contrastStd / 36) * 20 +
          10 -
          posePenalty
      )
    )
  );

  const spoofRiskFlag =
    (antispoofScore !== null && antispoofScore < 0.45) ||
    roiQ.sharpness < 4.5 ||
    roiQ.contrastStd < 11;

  const feedbackLabel = spoofRiskFlag
    ? 'Spoof / Quality Warning'
    : faceQualityScore >= 70
      ? 'Face Quality Good'
      : 'Acceptable Face Capture';

  return { faceQualityScore, spoofRiskFlag, feedbackLabel };
}

export function dotCosine(a: ArrayLike<number>, b: ArrayLike<number>): number {
  let s = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) s += a[i] * b[i];
  return Number(s.toFixed(4));
}

export interface ExtractedFaceFeatureResult {
  vector: number[];
  dim: number;
  featureVersion: string;
  box?: number[];
  boxRaw?: number[];
  quality: Record<string, unknown> & {
    meanBrightness?: number;
    contrastStd?: number;
    sharpness?: number;
    faceWidthPx?: number;
    faceHeightPx?: number;
    detectionConfidence?: number;
    landmarkCount?: number;
    poseYawDeg?: number;
    posePitchDeg?: number;
    poseRollDeg?: number;
    eyeAspectRatio?: number | null;
    noseXNorm?: number;
    antispoofScore?: number | null;
    livenessNetScore?: number | null;
    faceQualityScore?: number;
    spoofRiskFlag?: boolean;
    feedbackLabel?: string;
    model?: string;
  };
}

export interface MultiFrameCaptureOptions {
  challenge?: 'blink' | 'turn_left' | 'turn_right' | string;
  delayMs?: number;
  targetFrames?: number;
  minValidFrames?: number;
  maxAttempts?: number;
  maxDurationMs?: number;
  onProgress?: (info: {
    attempt: number;
    validCount: number;
    targetFrames: number;
    stage: string;
    lastFailureCode?: string;
    lastFailureMessage?: string;
  }) => void;
}

const FATAL_CAPTURE_CODES = new Set([
  'model_not_ready',
  'camera_not_ready',
  'unsupported_image_format',
]);

export async function orchestrateMultiFrameCapture<TSnapshot>(params: {
  captureSnapshot: () => TSnapshot | Promise<TSnapshot>;
  extractFrame: (
    snapshot: TSnapshot,
    meta: { frameMotionScore: number; attemptIndex: number; validIndex: number }
  ) => Promise<ExtractedFaceFeatureResult>;
  computeMotion: (snapA: TSnapshot, snapB: TSnapshot) => number;
  releaseSnapshot?: (snapshot: TSnapshot) => void;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  options?: MultiFrameCaptureOptions | number;
}): Promise<ExtractedFaceFeatureResult & { canvas: TSnapshot }> {
  const {
    captureSnapshot,
    extractFrame,
    computeMotion,
    releaseSnapshot,
    now = () => Date.now(),
    sleep = (ms: number) => new Promise((r) => setTimeout(r, ms)),
    options = 220,
  } = params;

  const optsObj: MultiFrameCaptureOptions =
    typeof options === 'number' ? { delayMs: options } : options || {};
  const challenge = optsObj.challenge;
  const targetFrames = optsObj.targetFrames ?? (challenge ? 4 : 3);
  const minValidFrames = Math.min(targetFrames, optsObj.minValidFrames ?? 3);
  const delayMs = optsObj.delayMs ?? (challenge ? 240 : 210);
  const retryDelayMs = Math.min(160, Math.max(90, Math.round(delayMs * 0.6)));
  const maxAttempts = optsObj.maxAttempts ?? Math.max(targetFrames + 5, targetFrames * 2 + 2);
  const maxDurationMs = optsObj.maxDurationMs ?? (challenge ? 7000 : 5000);

  const startedAt = now();
  const validItems: Array<{
    feat: ExtractedFaceFeatureResult;
    snapshot: TSnapshot;
    tMs: number;
    motionFromPrev: number;
  }> = [];
  const rejectedReasons: Array<{ attempt: number; code: string; feedbackLabel: string; message: string }> = [];

  let lastAcceptedSnapshot: TSnapshot | null = null;
  let lastValidTime = 0;
  let maxMotionScore = 0;
  let attempt = 0;

  try {
    while (validItems.length < targetFrames && attempt < maxAttempts) {
      if (attempt > 0 && now() - startedAt >= maxDurationMs) {
        break;
      }

      attempt += 1;
      const tMs = Math.max(lastValidTime + 1, Math.round(now()));
      const snap = await captureSnapshot();

      const pairMotion = lastAcceptedSnapshot ? computeMotion(lastAcceptedSnapshot, snap) : 0;
      const provisionalMaxMotion = Number(Math.max(maxMotionScore, pairMotion).toFixed(4));

      try {
        const feat = await extractFrame(snap, {
          frameMotionScore: provisionalMaxMotion,
          attemptIndex: attempt,
          validIndex: validItems.length,
        });

        maxMotionScore = provisionalMaxMotion;
        lastAcceptedSnapshot = snap;
        lastValidTime = tMs;
        validItems.push({
          feat,
          snapshot: snap,
          tMs,
          motionFromPrev: validItems.length === 0 ? 0 : pairMotion,
        });

        optsObj.onProgress?.({
          attempt,
          validCount: validItems.length,
          targetFrames,
          stage: 'frame_accepted',
        });

        if (validItems.length < targetFrames && attempt < maxAttempts && now() - startedAt < maxDurationMs) {
          await sleep(delayMs);
        }
      } catch (err) {
        const coded = err as Partial<CodedFaceError>;
        const code = coded?.code || 'frame_extraction_failed';
        const feedbackLabel = coded?.feedbackLabel || 'Rejected';
        const message = err instanceof Error ? err.message : String(err);

        // Recycle rejected snapshot if not stored in validItems
        if (releaseSnapshot && snap !== lastAcceptedSnapshot) {
          releaseSnapshot(snap);
        }

        rejectedReasons.push({ attempt, code, feedbackLabel, message });
        logFaceDiagnostic('warn', 'multi_frame', `Attempt ${attempt} rejected (${code}): ${message}`, {
          attempt,
          validCount: validItems.length,
          targetFrames,
          code,
        });

        if (FATAL_CAPTURE_CODES.has(code) || coded?.recoverable === false) {
          throw err;
        }

        optsObj.onProgress?.({
          attempt,
          validCount: validItems.length,
          targetFrames,
          stage: 'frame_retry',
          lastFailureCode: code,
          lastFailureMessage: message,
        });

        if (attempt < maxAttempts && now() - startedAt < maxDurationMs) {
          await sleep(retryDelayMs);
        }
      }
    }

    if (validItems.length < minValidFrames) {
      const lastReject = rejectedReasons[rejectedReasons.length - 1];
      const counts = new Map<string, number>();
      for (const r of rejectedReasons) {
        counts.set(r.code, (counts.get(r.code) || 0) + 1);
      }
      let dominant = lastReject;
      let maxCount = 0;
      for (const r of rejectedReasons) {
        const c = counts.get(r.code) || 0;
        if (c > maxCount) {
          maxCount = c;
          dominant = r;
        }
      }

      if (dominant) {
        throw createFaceError(
          dominant.code,
          dominant.feedbackLabel,
          validItems.length > 0
            ? `${dominant.message} (${validItems.length}/${minValidFrames} valid frames captured across ${attempt} attempts)`
            : dominant.message,
          {
            details: {
              validFrames: validItems.length,
              requiredFrames: minValidFrames,
              attempts: attempt,
              failureCodes: rejectedReasons.map((r) => r.code),
            },
          }
        );
      }
      throw createFaceError(
        'insufficient_valid_frames',
        'Capture Failed',
        `Unable to collect ${minValidFrames} valid face frames within capture window.`
      );
    }

    const minConsistency = challenge === 'turn_left' || challenge === 'turn_right' ? 0.72 : 0.78;

    // Evaluate mutual identity consistency across all accepted frames
    let frameConsistencyCosine = 1;
    for (let i = 0; i < validItems.length; i++) {
      for (let j = i + 1; j < validItems.length; j++) {
        const cos = dotCosine(validItems[i].feat.vector, validItems[j].feat.vector);
        if (cos < frameConsistencyCosine) frameConsistencyCosine = cos;
      }
    }
    frameConsistencyCosine = Number(frameConsistencyCosine.toFixed(4));

    if (frameConsistencyCosine < minConsistency) {
      throw createFaceError(
        'multi_frame_inconsistent',
        'Inconsistent Identity Across Frames',
        `Multi-frame consistency check failed (cosine=${frameConsistencyCosine} < ${minConsistency}). Keep a single steady subject in frame.`,
        {
          details: {
            frameConsistencyCosine,
            minConsistency,
            validFrames: validItems.length,
          },
        }
      );
    }

    const frameMotionScore = Number(maxMotionScore.toFixed(4));

    const earValues = validItems
      .map((x) => x.feat.quality?.eyeAspectRatio)
      .filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
    const eyeAspectRatioMin = earValues.length ? Number(Math.min(...earValues).toFixed(4)) : null;
    const eyeAspectRatioDelta =
      earValues.length >= 2 ? Number((Math.max(...earValues) - Math.min(...earValues)).toFixed(4)) : 0;
    const blinkDetected =
      earValues.length >= 2 && (eyeAspectRatioMin !== null && (eyeAspectRatioMin < 0.23 || eyeAspectRatioDelta >= 0.045));

    const yawValues = validItems
      .map((x) => x.feat.quality?.poseYawDeg)
      .filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
    const headYawDeltaDeg =
      yawValues.length >= 2 ? Number((Math.max(...yawValues) - Math.min(...yawValues)).toFixed(1)) : 0;

    // Preserve strict chronological ordering for server-side challenge trajectory validation
    const challengeFrames = validItems.map((item, idx) => {
      const q = item.feat.quality || {};
      const prevT = idx > 0 ? validItems[idx - 1].tMs : item.tMs - 1;
      const tMs = Math.max(prevT + 1, item.tMs);
      item.tMs = tMs;
      return {
        tMs,
        yawDeg: typeof q.poseYawDeg === 'number' ? q.poseYawDeg : 0,
        ...(typeof q.posePitchDeg === 'number' ? { pitchDeg: q.posePitchDeg } : {}),
        ...(typeof q.eyeAspectRatio === 'number' ? { ear: q.eyeAspectRatio } : {}),
        ...(typeof q.noseXNorm === 'number' ? { noseXNorm: q.noseXNorm } : {}),
        motionFromPrev: item.motionFromPrev,
      };
    });

    let challengeCompleted: boolean | undefined;
    if (challenge === 'blink') {
      challengeCompleted = blinkDetected;
    } else if (challenge === 'turn_left' || challenge === 'turn_right') {
      challengeCompleted = headYawDeltaDeg >= 5;
    }

    // Rank valid frames preferring sharp, high-quality, frontal pose
    const ranked = [...validItems].sort((a, b) => {
      const scoreA = (a.feat.quality?.faceQualityScore || 0) - Math.abs(a.feat.quality?.poseYawDeg || 0) * 0.5;
      const scoreB = (b.feat.quality?.faceQualityScore || 0) - Math.abs(b.feat.quality?.poseYawDeg || 0) * 0.5;
      return scoreB - scoreA;
    });
    const best = ranked[0];

    // Release non-best snapshots to keep memory bounded
    if (releaseSnapshot) {
      for (const item of validItems) {
        if (item !== best) releaseSnapshot(item.snapshot);
      }
    }

    best.feat.quality.multiFrameVerified = true;
    best.feat.quality.frameCount = validItems.length;
    best.feat.quality.attemptsUsed = attempt;
    best.feat.quality.discardedFrames = rejectedReasons.length;
    best.feat.quality.frameConsistencyCosine = frameConsistencyCosine;
    best.feat.quality.frameMotionScore = frameMotionScore;
    best.feat.quality.isLiveCapture = true;
    best.feat.quality.captureSource = 'webcam';
    best.feat.quality.challengeEvidence = { frames: challengeFrames };
    if (eyeAspectRatioMin !== null) best.feat.quality.eyeAspectRatioMin = eyeAspectRatioMin;
    best.feat.quality.eyeAspectRatioDelta = eyeAspectRatioDelta;
    best.feat.quality.blinkDetected = blinkDetected;
    best.feat.quality.headYawDeltaDeg = headYawDeltaDeg;
    if (challenge) {
      best.feat.quality.challengeType = challenge;
      best.feat.quality.challengeCompleted = Boolean(challengeCompleted);
    }

    logFaceDiagnostic('info', 'multi_frame', 'Multi-frame capture completed successfully', {
      validFrames: validItems.length,
      attempts: attempt,
      discarded: rejectedReasons.length,
      frameConsistencyCosine,
      frameMotionScore,
      faceQualityScore: best.feat.quality.faceQualityScore,
      challenge: challenge || null,
      challengeCompleted: challenge ? Boolean(challengeCompleted) : null,
    });

    return {
      ...best.feat,
      canvas: best.snapshot,
    };
  } catch (err) {
    if (releaseSnapshot) {
      for (const item of validItems) {
        releaseSnapshot(item.snapshot);
      }
    }
    throw err;
  }
}
