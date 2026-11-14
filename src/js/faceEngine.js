// Pretrained Deep Face Recognition, Alignment, Pose & Anti-Spoof Engine
// Powered by @vladmandic/human (BlazeFace + FaceMesh 468 landmarks + HSE-FaceRes 1024-D + AntiSpoof + Liveness)
// Model weights served locally from /models/human/ (zero external CDN runtime dependency)

import { Human } from '@vladmandic/human';
import { l2Normalize } from '../shared/voiceDsp.ts';

let humanInstance = null;
let initPromise = null;
let modelLoadStatus = 'idle'; // 'idle' | 'loading' | 'ready' | 'error'
let modelLoadError = '';

const HUMAN_CONFIG = {
  backend: 'webgl',
  modelBasePath: '/models/human/',
  debug: false,
  async: true,
  warmup: 'face',
  cacheModels: true,
  cacheSensitivity: 0.7,
  filter: { enabled: true, equalization: true, autoBrightness: true },
  face: {
    enabled: true,
    detector: {
      enabled: true,
      rotation: true, // Aligns tilted faces prior to embedding extraction
      maxDetected: 5,
      minConfidence: 0.42,
      iouThreshold: 0.3,
      scale: 1.4,
      return: false,
    },
    mesh: { enabled: true, keepInvalid: false },
    attention: { enabled: false },
    iris: { enabled: false },
    description: { enabled: true, minConfidence: 0.25 },
    emotion: { enabled: false },
    antispoof: { enabled: true },
    liveness: { enabled: true },
    gear: { enabled: false },
  },
  body: { enabled: false },
  hand: { enabled: false },
  object: { enabled: false },
  gesture: { enabled: false },
  segmentation: { enabled: false },
};

export function getFaceEngineStatus() {
  return {
    status: modelLoadStatus,
    error: modelLoadError,
    modelName: 'BlazeFace + FaceMesh + HSE-FaceRes (1024-D) + AntiSpoof',
  };
}

export async function ensureFaceEngineReady(onProgress) {
  if (humanInstance && modelLoadStatus === 'ready') return humanInstance;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    modelLoadStatus = 'loading';
    modelLoadError = '';
    if (onProgress) onProgress('Loading pretrained face recognition & anti-spoof models...');
    try {
      const h = new Human(HUMAN_CONFIG);
      try {
        await h.load();
      } catch {
        // Fallback to CPU backend if WebGL is unavailable in headless/restricted contexts
        h.config.backend = 'cpu';
        await h.load();
      }
      await h.warmup().catch(() => null);
      humanInstance = h;
      modelLoadStatus = 'ready';
      return h;
    } catch (err) {
      modelLoadStatus = 'error';
      modelLoadError = err instanceof Error ? err.message : 'Failed to load face ML models.';
      initPromise = null;
      throw new Error(`Face model initialization failed: ${modelLoadError}`, { cause: err });
    }
  })();

  return initPromise;
}

function measureRoiImageQuality(source, box) {
  const w = source.videoWidth || source.naturalWidth || source.width || 320;
  const h = source.videoHeight || source.naturalHeight || source.height || 240;
  const bx = Math.max(0, Math.floor(box?.[0] ?? 0));
  const by = Math.max(0, Math.floor(box?.[1] ?? 0));
  const bw = Math.max(32, Math.min(w - bx, Math.floor(box?.[2] ?? w)));
  const bh = Math.max(32, Math.min(h - by, Math.floor(box?.[3] ?? h)));

  const sampleSize = 96;
  const canvas = document.createElement('canvas');
  canvas.width = sampleSize;
  canvas.height = sampleSize;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, bx, by, bw, bh, 0, 0, sampleSize, sampleSize);
  const { data } = ctx.getImageData(0, 0, sampleSize, sampleSize);

  const gray = new Float32Array(sampleSize * sampleSize);
  let mean = 0;
  for (let i = 0; i < gray.length; i++) {
    const luma = 0.299 * data[i * 4] + 0.587 * data[i * 4 + 1] + 0.114 * data[i * 4 + 2];
    gray[i] = luma;
    mean += luma;
  }
  mean /= gray.length;

  let variance = 0;
  let lapSum = 0;
  let count = 0;
  for (let y = 1; y < sampleSize - 1; y++) {
    for (let x = 1; x < sampleSize - 1; x++) {
      const idx = y * sampleSize + x;
      variance += (gray[idx] - mean) ** 2;
      const lap = 4 * gray[idx] - gray[idx - 1] - gray[idx + 1] - gray[idx - sampleSize] - gray[idx + sampleSize];
      lapSum += lap * lap;
      count++;
    }
  }
  const contrastStd = Number(Math.sqrt(variance / gray.length).toFixed(1));
  const sharpness = Number(Math.sqrt(lapSum / Math.max(1, count)).toFixed(1));
  return {
    meanBrightness: Number(mean.toFixed(1)),
    contrastStd,
    sharpness,
    faceWidthPx: bw,
    faceHeightPx: bh,
  };
}

function ptDist(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) return 0;
  return Math.hypot((a[0] || 0) - (b[0] || 0), (a[1] || 0) - (b[1] || 0));
}

function eyeRatioFromAnnotations(upper, lower) {
  if (!Array.isArray(upper) || !Array.isArray(lower) || upper.length < 5 || lower.length < 5) return null;
  const hDist = ptDist(upper[0], upper[upper.length - 1]);
  if (hDist <= 1) return null;
  const v1 = ptDist(upper[Math.floor(upper.length * 0.35)], lower[Math.floor(lower.length * 0.35)]);
  const v2 = ptDist(upper[Math.floor(upper.length * 0.65)], lower[Math.floor(lower.length * 0.65)]);
  return (v1 + v2) / (2 * hDist);
}

function measureEyeAspectRatio(face) {
  const ann = face?.annotations;
  if (ann) {
    const lEar = eyeRatioFromAnnotations(ann.leftEyeUpper0, ann.leftEyeLower0);
    const rEar = eyeRatioFromAnnotations(ann.rightEyeUpper0, ann.rightEyeLower0);
    if (lEar !== null && rEar !== null) return Number(((lEar + rEar) / 2).toFixed(4));
    if (lEar !== null) return Number(lEar.toFixed(4));
    if (rEar !== null) return Number(rEar.toFixed(4));
  }
  const mesh = face?.mesh;
  if (Array.isArray(mesh) && mesh.length >= 388) {
    const lh = ptDist(mesh[33], mesh[133]);
    const lv = ptDist(mesh[159], mesh[145]);
    const rh = ptDist(mesh[362], mesh[263]);
    const rv = ptDist(mesh[386], mesh[374]);
    if (lh > 1 && rh > 1) {
      return Number((((lv / lh) + (rv / rh)) / 2).toFixed(4));
    }
  }
  return null;
}

// Fast live-preview check for webcam guidance overlay
export async function inspectLiveFaceGuidance(videoEl) {
  if (!videoEl || videoEl.readyState < 2) {
    return { status: 'waiting', feedbackLabel: 'Initializing Camera', message: 'Initializing camera feed...', ready: false };
  }
  const h = await ensureFaceEngineReady();
  const res = await h.detect(videoEl, {
    face: {
      description: { enabled: false },
      antispoof: { enabled: false },
      liveness: { enabled: false },
    },
  });
  const faces = res.face || [];
  if (faces.length === 0) {
    return { status: 'no_face', feedbackLabel: 'Face Not Detected', message: 'No face detected — position face inside guide oval', ready: false, count: 0 };
  }
  if (faces.length > 1) {
    return { status: 'multi_face', feedbackLabel: 'Multiple Faces Detected', message: `Multiple faces detected (${faces.length}) — ensure single subject only`, ready: false, count: faces.length, faces };
  }
  const f = faces[0];
  const [rx, ry, rw, rh] = f.boxRaw || [0, 0, 0, 0];
  const cx = rx + rw / 2;
  const cy = ry + rh / 2;
  const yawDeg = Math.round(((f.rotation?.angle?.yaw || 0) * 180) / Math.PI);
  const pitchDeg = Math.round(((f.rotation?.angle?.pitch || 0) * 180) / Math.PI);
  const roiQ = measureRoiImageQuality(videoEl, f.box);

  if (rw < 0.16 || rh < 0.2) {
    return { status: 'too_far', feedbackLabel: 'Face Too Far', message: 'Move slightly closer to camera', ready: false, face: f, roiQ };
  }
  if (cx < 0.25 || cx > 0.75 || cy < 0.22 || cy > 0.78) {
    return { status: 'off_center', feedbackLabel: 'Pose Off-Center', message: 'Center your face inside the oval guide', ready: false, face: f, roiQ };
  }
  if (Math.abs(yawDeg) > 25 || Math.abs(pitchDeg) > 22) {
    return { status: 'pose_angle', feedbackLabel: 'Pose Off-Center', message: `Look straight ahead (yaw ${yawDeg}°, pitch ${pitchDeg}°)`, ready: false, face: f, roiQ };
  }
  if (roiQ.meanBrightness < 38) {
    return { status: 'dark', feedbackLabel: 'Poor Lighting', message: 'Low lighting — move to brighter even light', ready: false, face: f, roiQ };
  }
  if (roiQ.sharpness < 4.5) {
    return { status: 'blur', feedbackLabel: 'Blurry Capture', message: 'Image looks blurry — hold steady briefly', ready: false, face: f, roiQ };
  }
  return {
    status: 'ready',
    feedbackLabel: 'Face Quality Good',
    message: 'Face aligned · Good lighting · Ready to capture',
    ready: true,
    face: f,
    roiQ,
    count: 1,
  };
}

// Extract authoritative 1024-D pretrained deep face embedding + quality + anti-spoof metadata
export async function extractPretrainedFaceFeatures(source, extraMeta = {}) {
  const h = await ensureFaceEngineReady();
  const res = await h.detect(source);
  const faces = res.face || [];

  if (faces.length === 0) {
    const err = new Error('Face Not Detected: Upload or capture a clear frontal face photo.');
    err.code = 'no_face_detected';
    err.feedbackLabel = 'Face Not Detected';
    throw err;
  }
  if (faces.length > 1) {
    const err = new Error(`Multiple Faces Detected (${faces.length}): Biometric enrollment and verification require exactly one subject.`);
    err.code = 'multiple_faces_detected';
    err.feedbackLabel = 'Multiple Faces Detected';
    throw err;
  }

  const face = faces[0];
  if (!face.embedding || face.embedding.length !== 1024) {
    const err = new Error('Blurry Capture: Face embedding extraction failed (landmark alignment confidence too low).');
    err.code = 'embedding_failed';
    err.feedbackLabel = 'Blurry Capture';
    throw err;
  }

  const yawDeg = Number((((face.rotation?.angle?.yaw || 0) * 180) / Math.PI).toFixed(1));
  const pitchDeg = Number((((face.rotation?.angle?.pitch || 0) * 180) / Math.PI).toFixed(1));
  const rollDeg = Number((((face.rotation?.angle?.roll || 0) * 180) / Math.PI).toFixed(1));

  if (Math.abs(yawDeg) > 36 || Math.abs(pitchDeg) > 32) {
    const err = new Error(`Pose Off-Center: Extreme face angle rejected (yaw ${yawDeg}°, pitch ${pitchDeg}°). Face the camera directly.`);
    err.code = 'extreme_face_pose';
    err.feedbackLabel = 'Pose Off-Center';
    throw err;
  }

  const roiQ = measureRoiImageQuality(source, face.box);
  if (roiQ.faceWidthPx < 44 || roiQ.faceHeightPx < 44) {
    const err = new Error(`Face Too Far: Detected face resolution too small (${roiQ.faceWidthPx}×${roiQ.faceHeightPx}px). Provide a closer or higher-resolution image.`);
    err.code = 'low_face_resolution';
    err.feedbackLabel = 'Face Too Far';
    throw err;
  }
  if (roiQ.meanBrightness < 26 || roiQ.meanBrightness > 238) {
    const err = new Error(`Poor Lighting: Unbalanced illumination (brightness ${roiQ.meanBrightness}/255). Use even front lighting.`);
    err.code = 'poor_illumination';
    err.feedbackLabel = 'Poor Lighting';
    throw err;
  }
  if (roiQ.contrastStd < 7 || roiQ.sharpness < 3.5) {
    const err = new Error(`Blurry Capture: Face ROI too blurry or flat (contrast=${roiQ.contrastStd}, sharpness=${roiQ.sharpness}).`);
    err.code = 'blurry_face_roi';
    err.feedbackLabel = 'Blurry Capture';
    throw err;
  }

  const antispoofScore = typeof face.real === 'number' ? Number(face.real.toFixed(3)) : null;
  const livenessNetScore = typeof face.live === 'number' ? Number(face.live.toFixed(3)) : null;
  const eyeAspectRatio = measureEyeAspectRatio(face);
  const detConf = Number((face.faceScore || face.boxScore || face.score || 0).toFixed(3));
  const posePenalty = (Math.abs(yawDeg) + Math.abs(pitchDeg) + Math.abs(rollDeg)) * 0.45;
  const faceQualityScore = Math.max(
    15,
    Math.min(
      100,
      Math.round(
        detConf * 45 +
          Math.min(1, roiQ.sharpness / 18) * 25 +
          Math.min(1, roiQ.contrastStd / 38) * 20 +
          10 -
          posePenalty
      )
    )
  );

  const spoofRiskFlag =
    (antispoofScore !== null && antispoofScore < 0.45) ||
    roiQ.sharpness < 5.5 ||
    roiQ.contrastStd < 12;

  const feedbackLabel = spoofRiskFlag
    ? 'Spoof / Quality Warning'
    : faceQualityScore >= 70
      ? 'Face Quality Good'
      : 'Acceptable Face Capture';

  return {
    vector: l2Normalize(Array.from(face.embedding)),
    dim: face.embedding.length,
    featureVersion: 'v2.0-multimodal',
    box: face.box,
    boxRaw: face.boxRaw,
    quality: {
      ...roiQ,
      detectionConfidence: detConf,
      poseYawDeg: yawDeg,
      posePitchDeg: pitchDeg,
      poseRollDeg: rollDeg,
      eyeAspectRatio,
      antispoofScore,
      livenessNetScore,
      faceQualityScore,
      spoofRiskFlag,
      feedbackLabel,
      model: 'blazeface+facemesh+faceres1024',
      ...extraMeta,
    },
  };
}

function snapshotVideoToCanvas(videoEl) {
  const canvas = document.createElement('canvas');
  canvas.width = videoEl.videoWidth || 640;
  canvas.height = videoEl.videoHeight || 480;
  canvas.getContext('2d').drawImage(videoEl, 0, 0, canvas.width, canvas.height);
  return canvas;
}

function computeCanvasMotion(cA, cB) {
  const size = 64;
  const sample = (c) => {
    const tmp = document.createElement('canvas');
    tmp.width = size;
    tmp.height = size;
    const ctx = tmp.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(c, 0, 0, size, size);
    const { data } = ctx.getImageData(0, 0, size, size);
    const out = new Float32Array(size * size);
    for (let i = 0; i < out.length; i++) {
      out[i] = (0.299 * data[i * 4] + 0.587 * data[i * 4 + 1] + 0.114 * data[i * 4 + 2]) / 255;
    }
    return out;
  };
  const a = sample(cA);
  const b = sample(cB);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff += Math.abs(a[i] - b[i]);
  return Number((diff / a.length).toFixed(4));
}

function dotCosine(a, b) {
  let s = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) s += a[i] * b[i];
  return Number(s.toFixed(4));
}

// Multi-frame live webcam capture: extracts 3–4 frames apart, checks motion, blink/head-turn challenge & inter-frame consistency
export async function captureMultiFrameFaceFeatures(videoEl, opts = 220) {
  if (!videoEl || videoEl.readyState < 2) {
    const err = new Error('Camera feed not ready for capture.');
    err.code = 'camera_not_ready';
    throw err;
  }
  const challenge = typeof opts === 'object' && opts ? opts.challenge : undefined;
  const delayMs = typeof opts === 'number' ? opts : (opts?.delayMs ?? (challenge ? 260 : 220));
  const targetFrames = challenge ? 4 : 3;

  const frames = [];
  for (let i = 0; i < targetFrames; i++) {
    frames.push(snapshotVideoToCanvas(videoEl));
    if (i < targetFrames - 1) {
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }

  let frameMotionScore = 0;
  for (let i = 0; i < frames.length - 1; i++) {
    frameMotionScore = Math.max(frameMotionScore, computeCanvasMotion(frames[i], frames[i + 1]));
  }
  frameMotionScore = Number(frameMotionScore.toFixed(4));

  const extracted = [];
  for (let i = 0; i < frames.length; i++) {
    const feat = await extractPretrainedFaceFeatures(frames[i], {
      captureSource: 'webcam',
      isLiveCapture: true,
      frameMotionScore,
    });
    extracted.push({ feat, canvas: frames[i] });
  }

  let frameConsistencyCosine = 1;
  for (let i = 0; i < extracted.length - 1; i++) {
    const cos = dotCosine(extracted[i].feat.vector, extracted[i + 1].feat.vector);
    frameConsistencyCosine = Math.min(frameConsistencyCosine, cos);
  }
  frameConsistencyCosine = Number(frameConsistencyCosine.toFixed(4));

  const minConsistency = challenge === 'turn_left' || challenge === 'turn_right' ? 0.72 : 0.78;
  if (frameConsistencyCosine < minConsistency) {
    const err = new Error(
      `Multi-frame consistency check failed (cosine=${frameConsistencyCosine} < ${minConsistency}). Hold steady in front of camera.`
    );
    err.code = 'multi_frame_inconsistent';
    err.feedbackLabel = 'Blurry Capture';
    throw err;
  }

  const earValues = extracted
    .map((x) => x.feat.quality?.eyeAspectRatio)
    .filter((v) => typeof v === 'number' && Number.isFinite(v));
  const eyeAspectRatioMin = earValues.length ? Number(Math.min(...earValues).toFixed(4)) : null;
  const eyeAspectRatioDelta =
    earValues.length >= 2 ? Number((Math.max(...earValues) - Math.min(...earValues)).toFixed(4)) : 0;
  const blinkDetected = earValues.length >= 2 && (eyeAspectRatioMin < 0.23 || eyeAspectRatioDelta >= 0.045);

  const yawValues = extracted
    .map((x) => x.feat.quality?.poseYawDeg)
    .filter((v) => typeof v === 'number' && Number.isFinite(v));
  const headYawDeltaDeg =
    yawValues.length >= 2 ? Number((Math.max(...yawValues) - Math.min(...yawValues)).toFixed(1)) : 0;

  let challengeCompleted;
  if (challenge === 'blink') {
    challengeCompleted = blinkDetected;
  } else if (challenge === 'turn_left' || challenge === 'turn_right') {
    challengeCompleted = headYawDeltaDeg >= 5;
  }

  // Prefer the most frontal frame as biometric embedding, retaining dynamic challenge telemetry
  extracted.sort((a, b) => {
    const scoreA = (a.feat.quality?.faceQualityScore || 0) - Math.abs(a.feat.quality?.poseYawDeg || 0) * 0.5;
    const scoreB = (b.feat.quality?.faceQualityScore || 0) - Math.abs(b.feat.quality?.poseYawDeg || 0) * 0.5;
    return scoreB - scoreA;
  });
  const best = extracted[0];
  best.feat.quality.multiFrameVerified = true;
  best.feat.quality.frameCount = frames.length;
  best.feat.quality.frameConsistencyCosine = frameConsistencyCosine;
  best.feat.quality.frameMotionScore = frameMotionScore;
  best.feat.quality.isLiveCapture = true;
  best.feat.quality.captureSource = 'webcam';
  if (eyeAspectRatioMin !== null) best.feat.quality.eyeAspectRatioMin = eyeAspectRatioMin;
  best.feat.quality.eyeAspectRatioDelta = eyeAspectRatioDelta;
  best.feat.quality.blinkDetected = blinkDetected;
  best.feat.quality.headYawDeltaDeg = headYawDeltaDeg;
  if (challenge) {
    best.feat.quality.challengeType = challenge;
    best.feat.quality.challengeCompleted = Boolean(challengeCompleted);
  }

  return {
    ...best.feat,
    canvas: best.canvas,
  };
}

