// Pretrained Deep Face Recognition, Alignment, Pose & Anti-Spoof Engine
// Powered by @vladmandic/human (BlazeFace + FaceMesh 468 landmarks + HSE-FaceRes 1024-D + AntiSpoof + Liveness)
// Model weights served locally from /models/human/ (zero external CDN runtime dependency)

import {
  FACE_EMBEDDING_DIM,
  createFaceError,
  createMutexQueue,
  evaluateFacePoseAndQuality,
  getFaceDiagnosticsConfig,
  logFaceDiagnostic,
  orchestrateMultiFrameCapture,
  runSerialized,
  setFaceDiagnosticsConfig,
  validateFaceEmbedding,
  validateFaceLandmarks,
} from '../shared/facePipeline.ts';

export { setFaceDiagnosticsConfig, getFaceDiagnosticsConfig };

let HumanCtor = null;
async function getHumanCtor() {
  if (!HumanCtor) {
    const mod = await import('@vladmandic/human');
    HumanCtor = mod.Human;
  }
  return HumanCtor;
}

let humanInstance = null;
let initPromise = null;
let modelLoadStatus = 'idle'; // 'idle' | 'loading' | 'ready' | 'error'
let modelLoadError = '';
let activeBackend = 'webgl';
let cpuFallbackAttempted = false;
let captureInFlightCount = 0;

const detectMutex = createMutexQueue();

// Scratch canvases reused for ROI quality & frame motion so retries do not leak DOM allocations
let roiScratchCanvas = null;
let motionScratchCanvas = null;

function getScratchCanvas(kind, size) {
  if (typeof document === 'undefined') return null;
  if (kind === 'roi') {
    if (!roiScratchCanvas) {
      roiScratchCanvas = document.createElement('canvas');
    }
    roiScratchCanvas.width = size;
    roiScratchCanvas.height = size;
    return roiScratchCanvas;
  }
  if (!motionScratchCanvas) {
    motionScratchCanvas = document.createElement('canvas');
  }
  motionScratchCanvas.width = size;
  motionScratchCanvas.height = size;
  return motionScratchCanvas;
}

function createBaseConfig(backend = 'webgl') {
  return {
    backend,
    modelBasePath: '/models/human/',
    debug: false,
    async: true,
    warmup: backend === 'cpu' ? 'none' : 'face',
    cacheModels: true,
    // Strictly disable inter-frame pixel caching so every capture & verification runs real inference
    cacheSensitivity: 0,
    // Disable Human's internal GL filter mutations (autoBrightness mutates config every frame)
    filter: {
      enabled: false,
      equalization: false,
      autoBrightness: false,
      return: false,
    },
    face: {
      enabled: true,
      detector: {
        enabled: true,
        rotation: true,
        maxDetected: 5,
        minConfidence: 0.42,
        iouThreshold: 0.3,
        scale: 1.4,
        skipFrames: 0,
        skipTime: 0,
        return: false,
      },
      mesh: {
        enabled: true,
        keepInvalid: false,
      },
      attention: { enabled: false },
      iris: { enabled: false },
      description: {
        enabled: true,
        minConfidence: 0.1,
        skipFrames: 0,
        skipTime: 0,
      },
      emotion: { enabled: false },
      antispoof: {
        enabled: true,
        skipFrames: 0,
        skipTime: 0,
      },
      liveness: {
        enabled: true,
        skipFrames: 0,
        skipTime: 0,
      },
      gear: { enabled: false },
    },
    body: { enabled: false },
    hand: { enabled: false },
    object: { enabled: false },
    gesture: { enabled: false },
    segmentation: { enabled: false },
  };
}

const EXTRACTION_DETECT_OVERRIDE = {
  cacheSensitivity: 0,
  filter: { enabled: false, equalization: false, autoBrightness: false, return: false },
  face: {
    enabled: true,
    detector: { enabled: true, rotation: true, skipFrames: 0, skipTime: 0 },
    mesh: { enabled: true, keepInvalid: false },
    description: { enabled: true, minConfidence: 0.1, skipFrames: 0, skipTime: 0 },
    antispoof: { enabled: true, skipFrames: 0, skipTime: 0 },
    liveness: { enabled: true, skipFrames: 0, skipTime: 0 },
  },
};

const GUIDANCE_DETECT_OVERRIDE = {
  cacheSensitivity: 0,
  filter: { enabled: false, equalization: false, autoBrightness: false, return: false },
  face: {
    enabled: true,
    detector: { enabled: true, rotation: true, skipFrames: 0, skipTime: 0 },
    mesh: { enabled: true, keepInvalid: false },
    description: { enabled: false },
    antispoof: { enabled: false },
    liveness: { enabled: false },
  },
};

function restoreFullFaceConfig(h) {
  if (!h?.config) return;
  h.config.cacheSensitivity = 0;
  if (h.config.filter) {
    h.config.filter.enabled = false;
    h.config.filter.equalization = false;
    h.config.filter.autoBrightness = false;
  }
  if (h.config.face?.detector) {
    h.config.face.detector.enabled = true;
    h.config.face.detector.skipFrames = 0;
    h.config.face.detector.skipTime = 0;
  }
  if (h.config.face?.mesh) {
    h.config.face.mesh.enabled = true;
  }
  if (h.config.face?.description) {
    h.config.face.description.enabled = true;
    h.config.face.description.skipFrames = 0;
    h.config.face.description.skipTime = 0;
  }
  if (h.config.face?.antispoof) {
    h.config.face.antispoof.enabled = true;
    h.config.face.antispoof.skipFrames = 0;
    h.config.face.antispoof.skipTime = 0;
  }
  if (h.config.face?.liveness) {
    h.config.face.liveness.enabled = true;
    h.config.face.liveness.skipFrames = 0;
    h.config.face.liveness.skipTime = 0;
  }
}

export function getFaceEngineStatus() {
  const modelsLoaded = humanInstance?.models?.models
    ? Object.entries(humanInstance.models.models)
        .filter(([, m]) => Boolean(m))
        .map(([k]) => k)
    : [];
  return {
    status: modelLoadStatus,
    error: modelLoadError,
    backend: activeBackend,
    modelsLoaded,
    modelName: 'BlazeFace + FaceMesh + HSE-FaceRes (1024-D) + AntiSpoof',
  };
}

async function initHumanWithBackend(Human, backend) {
  const h = new Human(createBaseConfig(backend));
  await h.load();
  // Ensure description model (faceres) actually loaded cleanly
  if (!h.models?.models?.faceres) {
    restoreFullFaceConfig(h);
    await h.load();
  }
  if (backend !== 'cpu') {
    await h.warmup().catch((err) => {
      logFaceDiagnostic('warn', 'warmup', `Warmup warning on ${backend}: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    });
  }
  restoreFullFaceConfig(h);
  return h;
}

export async function ensureFaceEngineReady(onProgress) {
  if (humanInstance && modelLoadStatus === 'ready') return humanInstance;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    modelLoadStatus = 'loading';
    modelLoadError = '';
    if (onProgress) onProgress('Loading pretrained face recognition & anti-spoof models...');
    try {
      const Human = await getHumanCtor();
      let h;
      try {
        activeBackend = 'webgl';
        h = await initHumanWithBackend(Human, 'webgl');
        cpuFallbackAttempted = false;
      } catch (webglErr) {
        logFaceDiagnostic('warn', 'init', `WebGL face backend unavailable, falling back to CPU: ${webglErr instanceof Error ? webglErr.message : String(webglErr)}`);
        activeBackend = 'cpu';
        cpuFallbackAttempted = true;
        h = await initHumanWithBackend(Human, 'cpu');
      }

      if (!h?.models?.models?.blazeface || !h?.models?.models?.facemesh || !h?.models?.models?.faceres) {
        throw createFaceError(
          'model_not_ready',
          'Model Not Ready',
          'Pretrained face detection or embedding model failed to finish loading from /models/human/.',
          {
            recoverable: false,
            details: {
              backend: activeBackend,
              hasBlazeface: Boolean(h?.models?.models?.blazeface),
              hasFacemesh: Boolean(h?.models?.models?.facemesh),
              hasFaceres: Boolean(h?.models?.models?.faceres),
            },
          }
        );
      }

      humanInstance = h;
      modelLoadStatus = 'ready';
      logFaceDiagnostic('info', 'init', `Face engine ready on backend=${activeBackend}`, {
        backend: activeBackend,
        models: Object.keys(h.models.models).filter((k) => Boolean(h.models.models[k])),
      });
      return h;
    } catch (err) {
      modelLoadStatus = 'error';
      modelLoadError = err instanceof Error ? err.message : 'Failed to load face ML models.';
      humanInstance = null;
      initPromise = null;
      logFaceDiagnostic('error', 'init', `Face engine initialization failed: ${modelLoadError}`);
      if (err?.code) throw err;
      throw createFaceError(
        'model_not_ready',
        'Model Not Ready',
        `Face model initialization failed: ${modelLoadError}`,
        { recoverable: false, cause: err }
      );
    }
  })();

  return initPromise;
}

async function switchToCpuFallback(reason) {
  if (cpuFallbackAttempted || activeBackend === 'cpu') return null;
  cpuFallbackAttempted = true;
  logFaceDiagnostic('warn', 'backend_fallback', `Switching face engine to CPU fallback: ${reason}`);
  const Human = await getHumanCtor();
  humanInstance = null;
  initPromise = null;
  activeBackend = 'cpu';
  modelLoadStatus = 'loading';
  const h = await initHumanWithBackend(Human, 'cpu');
  humanInstance = h;
  modelLoadStatus = 'ready';
  return h;
}

function validateAndGetSourceDims(source) {
  if (!source) {
    throw createFaceError(
      'unsupported_image_format',
      'Invalid Input',
      'No image or video frame was provided for face analysis.',
      { recoverable: false }
    );
  }

  const isVideo = typeof HTMLVideoElement !== 'undefined' && source instanceof HTMLVideoElement;
  if (isVideo) {
    if (source.readyState < 2 || !source.videoWidth || !source.videoHeight) {
      throw createFaceError(
        'camera_frame_not_ready',
        'Camera Not Ready',
        'Camera frame is not decoded yet. Wait a moment for live video dimensions to stabilize.'
      );
    }
    return { width: source.videoWidth, height: source.videoHeight, kind: 'video' };
  }

  const isImg = typeof HTMLImageElement !== 'undefined' && source instanceof HTMLImageElement;
  if (isImg) {
    if (!source.complete || !source.naturalWidth || !source.naturalHeight) {
      throw createFaceError(
        'unsupported_image_format',
        'Invalid Image',
        'Uploaded image failed to decode or has zero dimensions.',
        { recoverable: false }
      );
    }
    return { width: source.naturalWidth, height: source.naturalHeight, kind: 'image' };
  }

  const width = source.videoWidth || source.naturalWidth || source.width || 0;
  const height = source.videoHeight || source.naturalHeight || source.height || 0;
  if (!width || !height) {
    throw createFaceError(
      'unsupported_image_format',
      'Invalid Image',
      'Unsupported image or frame format (zero width or height).',
      { recoverable: false }
    );
  }
  return { width, height, kind: 'canvas' };
}

async function runSerializedDetect(source, mode = 'extract') {
  return runSerialized(detectMutex, async () => {
    const h = await ensureFaceEngineReady();
    if (!h?.models?.models?.faceres && mode === 'extract') {
      restoreFullFaceConfig(h);
      await h.load();
    }
    const override = mode === 'guidance' ? GUIDANCE_DETECT_OVERRIDE : EXTRACTION_DETECT_OVERRIDE;
    try {
      const result = await h.detect(source, override);
      return { result, backend: activeBackend };
    } finally {
      // Never leave singleton Human instance with description/antispoof/liveness disabled
      restoreFullFaceConfig(h);
    }
  });
}

function measureRoiImageQuality(source, box, dims) {
  const w = dims?.width || source.videoWidth || source.naturalWidth || source.width || 320;
  const h = dims?.height || source.videoHeight || source.naturalHeight || source.height || 240;

  const rawX = Math.floor(box?.[0] ?? 0);
  const rawY = Math.floor(box?.[1] ?? 0);
  const rawW = Math.floor(box?.[2] ?? w);
  const rawH = Math.floor(box?.[3] ?? h);

  const bx = Math.max(0, Math.min(w - 1, rawX));
  const by = Math.max(0, Math.min(h - 1, rawY));
  const adjW = rawX < 0 ? rawW + rawX : rawW;
  const adjH = rawY < 0 ? rawH + rawY : rawH;
  const bw = Math.max(1, Math.min(w - bx, Math.max(16, adjW)));
  const bh = Math.max(1, Math.min(h - by, Math.max(16, adjH)));

  const sampleSize = 96;
  const canvas = getScratchCanvas('roi', sampleSize);
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
    faceWidthPx: rawW,
    faceHeightPx: rawH,
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

// Fast live-preview check for webcam guidance overlay (automatically yields when capture is running)
export async function inspectLiveFaceGuidance(videoEl) {
  if (captureInFlightCount > 0) {
    return {
      status: 'capturing',
      feedbackLabel: 'Capturing...',
      message: 'Analyzing live frames — hold steady...',
      ready: false,
      paused: true,
    };
  }
  if (!videoEl || videoEl.readyState < 2 || !videoEl.videoWidth || !videoEl.videoHeight) {
    return {
      status: 'waiting',
      feedbackLabel: 'Initializing Camera',
      message: 'Initializing camera feed...',
      ready: false,
    };
  }

  const { result: res } = await runSerializedDetect(videoEl, 'guidance');
  const faces = res?.face || [];
  if (faces.length === 0) {
    return {
      status: 'no_face',
      feedbackLabel: 'Face Not Detected',
      message: 'No face detected — position face inside guide oval',
      ready: false,
      count: 0,
    };
  }
  if (faces.length > 1) {
    return {
      status: 'multi_face',
      feedbackLabel: 'Multiple Faces Detected',
      message: `Multiple faces detected (${faces.length}) — ensure single subject only`,
      ready: false,
      count: faces.length,
    };
  }

  const f = faces[0];
  const [rx, ry, rw, rh] = f.boxRaw || [0, 0, 0, 0];
  const cx = rx + rw / 2;
  const cy = ry + rh / 2;
  const yawDeg = Math.round(((f.rotation?.angle?.yaw || 0) * 180) / Math.PI);
  const pitchDeg = Math.round(((f.rotation?.angle?.pitch || 0) * 180) / Math.PI);
  const dims = { width: videoEl.videoWidth, height: videoEl.videoHeight };
  const roiQ = measureRoiImageQuality(videoEl, f.box, dims);

  if (rw < 0.16 || rh < 0.2) {
    return { status: 'too_far', feedbackLabel: 'Face Too Far', message: 'Move slightly closer to camera', ready: false, roiQ };
  }
  if (cx < 0.22 || cx > 0.78 || cy < 0.2 || cy > 0.8) {
    return { status: 'off_center', feedbackLabel: 'Pose Off-Center', message: 'Center your face inside the oval guide', ready: false, roiQ };
  }
  if (Math.abs(yawDeg) > 25 || Math.abs(pitchDeg) > 22) {
    return { status: 'pose_angle', feedbackLabel: 'Pose Off-Center', message: `Look straight ahead (yaw ${yawDeg}°, pitch ${pitchDeg}°)`, ready: false, roiQ };
  }
  if (roiQ.meanBrightness < 32 || roiQ.meanBrightness > 235) {
    return { status: 'dark', feedbackLabel: 'Poor Lighting', message: 'Adjust lighting — use even front illumination', ready: false, roiQ };
  }
  if (roiQ.sharpness < 3.2) {
    return { status: 'blur', feedbackLabel: 'Motion Blur', message: 'Image looks soft — hold steady briefly', ready: false, roiQ };
  }
  return {
    status: 'ready',
    feedbackLabel: 'Face Quality Good',
    message: 'Face aligned · Good lighting · Ready to capture',
    ready: true,
    roiQ,
    count: 1,
  };
}

// Extract authoritative 1024-D pretrained deep face embedding + quality + anti-spoof metadata
export async function extractPretrainedFaceFeatures(source, extraMeta = {}) {
  const dims = validateAndGetSourceDims(source);

  let detected;
  try {
    detected = await runSerializedDetect(source, 'extract');
  } catch (err) {
    if (err?.code) throw err;
    if (activeBackend !== 'cpu' && !cpuFallbackAttempted) {
      await runSerialized(detectMutex, () =>
        switchToCpuFallback(err instanceof Error ? err.message : 'inference exception')
      );
      detected = await runSerializedDetect(source, 'extract');
    } else {
      throw createFaceError(
        'embedding_model_inference_failed',
        'Model Inference Failure',
        `Face inference engine error: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err }
      );
    }
  }

  let { result: res } = detected;
  let faces = res?.face || [];

  if (faces.length === 0) {
    throw createFaceError(
      'no_face_detected',
      'Face Not Detected',
      'Face Not Detected: Position a single clear frontal face inside the frame.'
    );
  }
  if (faces.length > 1) {
    throw createFaceError(
      'multiple_faces_detected',
      'Multiple Faces Detected',
      `Multiple Faces Detected (${faces.length}): Biometric enrollment and verification require exactly one subject.`
    );
  }

  let face = faces[0];
  let landmarkInfo = validateFaceLandmarks(face, dims.width);

  let embeddingResult;
  try {
    embeddingResult = validateFaceEmbedding(face.embedding, FACE_EMBEDDING_DIM, {
      descriptionEnabled: humanInstance?.config?.face?.description?.enabled,
      backend: activeBackend,
    });
  } catch (embErr) {
    logFaceDiagnostic('warn', 'extract', `Initial embedding validation failed: ${embErr.message}`, {
      code: embErr.code,
      backend: activeBackend,
      landmarkCount: landmarkInfo.landmarkCount,
      detConf: landmarkInfo.detectionConfidence,
    });

    // Recover automatically from transient WebGL NaN/context failure via one-time CPU fallback
    if (
      activeBackend !== 'cpu' &&
      !cpuFallbackAttempted &&
      (embErr.code === 'embedding_model_inference_failed' ||
        embErr.code === 'invalid_embedding_nan' ||
        embErr.code === 'degenerate_embedding_vector')
    ) {
      await runSerialized(detectMutex, () => switchToCpuFallback(embErr.code));
      const retry = await runSerializedDetect(source, 'extract');
      res = retry.result;
      faces = res?.face || [];
      if (faces.length !== 1) throw embErr;
      face = faces[0];
      landmarkInfo = validateFaceLandmarks(face, dims.width);
      embeddingResult = validateFaceEmbedding(face.embedding, FACE_EMBEDDING_DIM, {
        descriptionEnabled: humanInstance?.config?.face?.description?.enabled,
        backend: activeBackend,
      });
    } else {
      throw embErr;
    }
  }

  const pose = {
    yawDeg: Number((((face.rotation?.angle?.yaw || 0) * 180) / Math.PI).toFixed(1)),
    pitchDeg: Number((((face.rotation?.angle?.pitch || 0) * 180) / Math.PI).toFixed(1)),
    rollDeg: Number((((face.rotation?.angle?.roll || 0) * 180) / Math.PI).toFixed(1)),
  };

  const roiQ = measureRoiImageQuality(source, face.box, dims);
  const antispoofScore = typeof face.real === 'number' && Number.isFinite(face.real) ? Number(face.real.toFixed(3)) : null;
  const livenessNetScore = typeof face.live === 'number' && Number.isFinite(face.live) ? Number(face.live.toFixed(3)) : null;

  const qualityEval = evaluateFacePoseAndQuality({
    pose,
    roiQ,
    detectionConfidence: landmarkInfo.detectionConfidence,
    antispoofScore,
    livenessNetScore,
    isLiveCapture: Boolean(extraMeta?.isLiveCapture),
  });

  const eyeAspectRatio = measureEyeAspectRatio(face);

  logFaceDiagnostic('debug', 'extract', 'Face embedding extracted', {
    dim: embeddingResult.dim,
    backend: activeBackend,
    landmarkCount: landmarkInfo.landmarkCount,
    detectionConfidence: landmarkInfo.detectionConfidence,
    yawDeg: pose.yawDeg,
    pitchDeg: pose.pitchDeg,
    sharpness: roiQ.sharpness,
    contrastStd: roiQ.contrastStd,
    meanBrightness: roiQ.meanBrightness,
    faceQualityScore: qualityEval.faceQualityScore,
  });

  return {
    vector: embeddingResult.vector,
    dim: embeddingResult.dim,
    featureVersion: 'v2.0-multimodal',
    box: face.box,
    boxRaw: face.boxRaw,
    quality: {
      ...roiQ,
      detectionConfidence: landmarkInfo.detectionConfidence,
      landmarkCount: landmarkInfo.landmarkCount,
      poseYawDeg: pose.yawDeg,
      posePitchDeg: pose.pitchDeg,
      poseRollDeg: pose.rollDeg,
      eyeAspectRatio,
      ...(landmarkInfo.noseXNorm !== undefined ? { noseXNorm: landmarkInfo.noseXNorm } : {}),
      antispoofScore,
      livenessNetScore,
      faceQualityScore: qualityEval.faceQualityScore,
      spoofRiskFlag: qualityEval.spoofRiskFlag,
      feedbackLabel: qualityEval.feedbackLabel,
      model: 'blazeface+facemesh+faceres1024',
      backend: activeBackend,
      ...extraMeta,
    },
  };
}

function snapshotVideoToCanvas(videoEl) {
  if (!videoEl || videoEl.readyState < 2 || !videoEl.videoWidth || !videoEl.videoHeight) {
    throw createFaceError(
      'camera_frame_not_ready',
      'Camera Not Ready',
      'Camera frame not ready for capture. Wait for video stream dimensions to initialize.'
    );
  }
  const canvas = document.createElement('canvas');
  canvas.width = videoEl.videoWidth;
  canvas.height = videoEl.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
  return canvas;
}

function releaseCanvasSnapshot(canvas) {
  if (!canvas || typeof canvas !== 'object') return;
  try {
    canvas.width = 0;
    canvas.height = 0;
  } catch {
    // Ignore detached canvas cleanup errors
  }
}

function computeCanvasMotion(cA, cB) {
  const size = 64;
  const tmp = getScratchCanvas('motion', size);
  const ctx = tmp.getContext('2d', { willReadFrequently: true });
  const sample = (c) => {
    ctx.clearRect(0, 0, size, size);
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

// Resilient multi-frame live webcam capture: evaluates each frame independently with bounded retries,
// preserves dynamic challenge trajectory timing & inter-frame consistency, and keeps camera stable.
export async function captureMultiFrameFaceFeatures(videoEl, opts = 220) {
  if (!videoEl || videoEl.readyState < 2 || !videoEl.videoWidth || !videoEl.videoHeight) {
    throw createFaceError(
      'camera_not_ready',
      'Camera Not Ready',
      'Camera feed not ready for capture.'
    );
  }

  captureInFlightCount += 1;
  try {
    await ensureFaceEngineReady();
    return await orchestrateMultiFrameCapture({
      captureSnapshot: () => snapshotVideoToCanvas(videoEl),
      extractFrame: (snapshot, { frameMotionScore }) =>
        extractPretrainedFaceFeatures(snapshot, {
          captureSource: 'webcam',
          isLiveCapture: true,
          frameMotionScore,
        }),
      computeMotion: computeCanvasMotion,
      releaseSnapshot: releaseCanvasSnapshot,
      options: opts,
    });
  } finally {
    captureInFlightCount = Math.max(0, captureInFlightCount - 1);
  }
}
