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
      } catch (webglErr) {
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
      throw new Error(`Face model initialization failed: ${modelLoadError}`);
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

// Fast live-preview check for webcam guidance overlay
export async function inspectLiveFaceGuidance(videoEl) {
  if (!videoEl || videoEl.readyState < 2) {
    return { status: 'waiting', message: 'Initializing camera feed...', ready: false };
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
    return { status: 'no_face', message: 'No face detected — position face inside guide oval', ready: false, count: 0 };
  }
  if (faces.length > 1) {
    return { status: 'multi_face', message: `Multiple faces detected (${faces.length}) — ensure single subject only`, ready: false, count: faces.length, faces };
  }
  const f = faces[0];
  const [rx, ry, rw, rh] = f.boxRaw || [0, 0, 0, 0];
  const cx = rx + rw / 2;
  const cy = ry + rh / 2;
  const yawDeg = Math.round(((f.rotation?.angle?.yaw || 0) * 180) / Math.PI);
  const pitchDeg = Math.round(((f.rotation?.angle?.pitch || 0) * 180) / Math.PI);
  const roiQ = measureRoiImageQuality(videoEl, f.box);

  if (rw < 0.16 || rh < 0.2) {
    return { status: 'too_far', message: 'Move slightly closer to camera', ready: false, face: f, roiQ };
  }
  if (cx < 0.25 || cx > 0.75 || cy < 0.22 || cy > 0.78) {
    return { status: 'off_center', message: 'Center your face inside the oval guide', ready: false, face: f, roiQ };
  }
  if (Math.abs(yawDeg) > 25 || Math.abs(pitchDeg) > 22) {
    return { status: 'pose_angle', message: `Look straight ahead (yaw ${yawDeg}°, pitch ${pitchDeg}°)`, ready: false, face: f, roiQ };
  }
  if (roiQ.meanBrightness < 38) {
    return { status: 'dark', message: 'Low lighting — move to brighter even light', ready: false, face: f, roiQ };
  }
  if (roiQ.sharpness < 4.5) {
    return { status: 'blur', message: 'Image looks blurry — hold steady briefly', ready: false, face: f, roiQ };
  }
  return {
    status: 'ready',
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
    const err = new Error('No human face detected. Upload or capture a clear frontal face photo.');
    err.code = 'no_face_detected';
    throw err;
  }
  if (faces.length > 1) {
    const err = new Error(`Multiple faces detected (${faces.length}). Biometric enrollment and verification require exactly one subject.`);
    err.code = 'multiple_faces_detected';
    throw err;
  }

  const face = faces[0];
  if (!face.embedding || face.embedding.length !== 1024) {
    const err = new Error('Face embedding extraction failed (face landmark alignment confidence too low).');
    err.code = 'embedding_failed';
    throw err;
  }

  const yawDeg = Number((((face.rotation?.angle?.yaw || 0) * 180) / Math.PI).toFixed(1));
  const pitchDeg = Number((((face.rotation?.angle?.pitch || 0) * 180) / Math.PI).toFixed(1));
  const rollDeg = Number((((face.rotation?.angle?.roll || 0) * 180) / Math.PI).toFixed(1));

  if (Math.abs(yawDeg) > 36 || Math.abs(pitchDeg) > 32) {
    const err = new Error(`Extreme face angle rejected (yaw ${yawDeg}°, pitch ${pitchDeg}°). Face the camera directly.`);
    err.code = 'extreme_face_pose';
    throw err;
  }

  const roiQ = measureRoiImageQuality(source, face.box);
  if (roiQ.faceWidthPx < 44 || roiQ.faceHeightPx < 44) {
    const err = new Error(`Detected face resolution too small (${roiQ.faceWidthPx}×${roiQ.faceHeightPx}px). Provide a closer or higher-resolution image.`);
    err.code = 'low_face_resolution';
    throw err;
  }
  if (roiQ.meanBrightness < 26 || roiQ.meanBrightness > 238) {
    const err = new Error(`Poor face illumination (brightness ${roiQ.meanBrightness}/255). Use even front lighting.`);
    err.code = 'poor_illumination';
    throw err;
  }
  if (roiQ.contrastStd < 7 || roiQ.sharpness < 3.5) {
    const err = new Error(`Face ROI too blurry or flat (contrast=${roiQ.contrastStd}, sharpness=${roiQ.sharpness}).`);
    err.code = 'blurry_face_roi';
    throw err;
  }

  const antispoofScore = typeof face.real === 'number' ? Number(face.real.toFixed(3)) : null;
  const livenessNetScore = typeof face.live === 'number' ? Number(face.live.toFixed(3)) : null;
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
      antispoofScore,
      livenessNetScore,
      faceQualityScore,
      spoofRiskFlag,
      model: 'blazeface+facemesh+faceres1024',
      ...extraMeta,
    },
  };
}
