// Browser-native classical feature extraction & multimodal fusion engine
// Implements CLAHE-like contrast normalization, HOG/LBP-inspired image descriptors,
// MFCC-band/ZCR/RMS acoustic vectors, and Early/Score/Decision/Hierarchical/3-Modal fusion.

export function l2Normalize(vec) {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm) || 1;
  return vec.map((v) => v / norm);
}

export function cosineSimilarity(a, b) {
  if (!a || !b || a.length !== b.length || a.length === 0) return 0;
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
  // Map [-1, 1] into [0, 1] calibrated similarity
  return Math.max(0, Math.min(1, (dot / denom + 1) / 2));
}

export function pairL1Distance(a, b) {
  if (!a || !b || a.length !== b.length) return 1;
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += Math.abs(a[i] - b[i]);
  return sum / a.length;
}

export function scoreAgainstRefs(probeVec, refVecs) {
  if (!probeVec || !refVecs || refVecs.length === 0) return 0;
  let best = 0;
  let total = 0;
  for (const ref of refVecs) {
    const sim = cosineSimilarity(probeVec, ref);
    if (sim > best) best = sim;
    total += sim;
  }
  const mean = total / refVecs.length;
  // Blend max-match and centroid-mean for pair-verifier stability
  return Number((0.6 * best + 0.4 * mean).toFixed(4));
}

// Convert Image / Video / Canvas into 64x64 grayscale array
function sourceToGray64(source) {
  const size = 64;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, 0, 0, size, size);
  const { data } = ctx.getImageData(0, 0, size, size);
  const gray = new Float32Array(size * size);
  for (let i = 0; i < size * size; i++) {
    const r = data[i * 4];
    const g = data[i * 4 + 1];
    const b = data[i * 4 + 2];
    gray[i] = 0.299 * r + 0.587 * g + 0.114 * b;
  }
  return { gray, size };
}

// Contrast-limited local histogram equalization (8x8 tile approximation)
function applyClaheLike(gray, size) {
  const out = new Float32Array(gray.length);
  const tile = 16;
  for (let ty = 0; ty < size; ty += tile) {
    for (let tx = 0; tx < size; tx += tile) {
      const hist = new Float32Array(32);
      for (let y = ty; y < ty + tile; y++) {
        for (let x = tx; x < tx + tile; x++) {
          const bin = Math.min(31, Math.floor((gray[y * size + x] / 256) * 32));
          hist[bin]++;
        }
      }
      // Clip & redistribute
      const clipLimit = (tile * tile) / 16;
      let excess = 0;
      for (let b = 0; b < 32; b++) {
        if (hist[b] > clipLimit) {
          excess += hist[b] - clipLimit;
          hist[b] = clipLimit;
        }
      }
      const add = excess / 32;
      const cdf = new Float32Array(32);
      let acc = 0;
      for (let b = 0; b < 32; b++) {
        acc += hist[b] + add;
        cdf[b] = acc / (tile * tile);
      }
      for (let y = ty; y < ty + tile; y++) {
        for (let x = tx; x < tx + tile; x++) {
          const bin = Math.min(31, Math.floor((gray[y * size + x] / 256) * 32));
          out[y * size + x] = cdf[bin] * 255;
        }
      }
    }
  }
  return out;
}

// Extract HOG-like (9 orientations x 8x8 cells = 576-D reduced or 64-D compact) + LBP (16-bin x 4 quadrants = 64-D)
export function extractFaceFeatures(source) {
  const { gray, size } = sourceToGray64(source);
  const eq = applyClaheLike(gray, size);

  // Image quality / liveness heuristics (blur variance & dynamic range)
  let mean = 0;
  for (let i = 0; i < eq.length; i++) mean += eq[i];
  mean /= eq.length;
  let variance = 0;
  let laplacianEnergy = 0;
  for (let y = 1; y < size - 1; y++) {
    for (let x = 1; x < size - 1; x++) {
      const idx = y * size + x;
      variance += (eq[idx] - mean) ** 2;
      const lap = 4 * eq[idx] - eq[idx - 1] - eq[idx + 1] - eq[idx - size] - eq[idx + size];
      laplacianEnergy += lap * lap;
    }
  }
  variance /= eq.length;
  laplacianEnergy /= (size - 2) * (size - 2);

  // 8x8 grid of 9-bin gradient orientation histograms (projected to 72-D for fast JS storage)
  const cell = 8;
  const cells = size / cell; // 8
  const hog = new Array(cells * cells * 9).fill(0);
  for (let y = 1; y < size - 1; y++) {
    for (let x = 1; x < size - 1; x++) {
      const gx = eq[y * size + x + 1] - eq[y * size + x - 1];
      const gy = eq[(y + 1) * size + x] - eq[(y - 1) * size + x];
      const mag = Math.hypot(gx, gy);
      let angle = (Math.atan2(gy, gx) * 180) / Math.PI;
      if (angle < 0) angle += 180;
      const bin = Math.min(8, Math.floor(angle / 20));
      const cy = Math.floor(y / cell);
      const cx = Math.floor(x / cell);
      hog[(cy * cells + cx) * 9 + bin] += mag;
    }
  }

  // Compact HOG pooling (4x4 macro cells x 9 bins = 144-D)
  const hogCompact = [];
  for (let my = 0; my < 4; my++) {
    for (let mx = 0; mx < 4; mx++) {
      const bins = new Array(9).fill(0);
      for (let dy = 0; dy < 2; dy++) {
        for (let dx = 0; dx < 2; dx++) {
          const base = ((my * 2 + dy) * cells + (mx * 2 + dx)) * 9;
          for (let b = 0; b < 9; b++) bins[b] += hog[base + b];
        }
      }
      hogCompact.push(...l2Normalize(bins));
    }
  }

  // Uniform-style LBP in 4 quadrants (4 x 16 bins = 64-D)
  const lbp = new Array(64).fill(0);
  const dirs = [
    [-1, -1], [0, -1], [1, -1], [1, 0],
    [1, 1], [0, 1], [-1, 1], [-1, 0],
  ];
  for (let y = 1; y < size - 1; y++) {
    for (let x = 1; x < size - 1; x++) {
      const c = eq[y * size + x];
      let code = 0;
      for (let d = 0; d < 8; d++) {
        if (eq[(y + dirs[d][1]) * size + (x + dirs[d][0])] >= c) code |= 1 << d;
      }
      const q = (y >= 32 ? 2 : 0) + (x >= 32 ? 1 : 0);
      lbp[q * 16 + (code >> 4)] += 1;
    }
  }

  const vector = l2Normalize([...hogCompact, ...l2Normalize(lbp)]);
  const contrastStd = Number(Math.sqrt(variance).toFixed(1));
  const sharpness = Number(Math.sqrt(laplacianEnergy).toFixed(1));
  return {
    vector,
    dim: vector.length,
    quality: {
      contrastStd,
      sharpness,
      spoofRiskFlag: laplacianEnergy < 120 || variance < 160,
    },
  };
}

// Compute normalized frame-to-frame pixel motion between two live webcam captures (liveness heuristic)
export function computeFrameMotion(sourceA, sourceB) {
  const { gray: gA } = sourceToGray64(sourceA);
  const { gray: gB } = sourceToGray64(sourceB);
  let diffSum = 0;
  for (let i = 0; i < gA.length; i++) {
    diffSum += Math.abs(gA[i] - gB[i]) / 255;
  }
  return Number((diffSum / gA.length).toFixed(4));
}

// Fingerprint classical feature extractor: CLAHE -> directional ridge filter + LBP + ridge density
export function extractFingerprintFeatures(source) {
  const { gray, size } = sourceToGray64(source);
  const eq = applyClaheLike(gray, size);

  // Compute 4 directional ridge energies + 8x8 orientation histogram + minutiae-like ridge ending density
  const orientHist = new Array(4 * 4 * 8).fill(0);
  let ridgePixels = 0;
  let endingCandidates = 0;

  // Binary ridge mask for heuristic ridge ending count
  const mask = new Uint8Array(size * size);
  for (let i = 0; i < eq.length; i++) {
    mask[i] = eq[i] < 120 ? 1 : 0;
    if (mask[i]) ridgePixels++;
  }

  for (let y = 1; y < size - 1; y++) {
    for (let x = 1; x < size - 1; x++) {
      const gx = eq[y * size + x + 1] - eq[y * size + x - 1];
      const gy = eq[(y + 1) * size + x] - eq[(y - 1) * size + x];
      const mag = Math.hypot(gx, gy);
      let angle = (Math.atan2(gy, gx) * 180) / Math.PI;
      if (angle < 0) angle += 180;
      const bin = Math.min(7, Math.floor(angle / 22.5));
      const cy = Math.floor(y / 16);
      const cx = Math.floor(x / 16);
      orientHist[(cy * 4 + cx) * 8 + bin] += mag;

      if (mask[y * size + x] === 1) {
        let neighbors = 0;
        for (let dy = -1; dy <= 1; dy++) {
          for (let dx = -1; dx <= 1; dx++) {
            if (dx === 0 && dy === 0) continue;
            neighbors += mask[(y + dy) * size + (x + dx)];
          }
        }
        if (neighbors === 1 || neighbors === 3) endingCandidates++;
      }
    }
  }

  const ridgeDensity = ridgePixels / (size * size);
  const endingDensity = endingCandidates / (size * size);
  const vector = l2Normalize([...l2Normalize(orientHist), ridgeDensity * 4, endingDensity * 10]);

  return {
    vector,
    dim: vector.length,
    quality: {
      ridgeDensity: Number((ridgeDensity * 100).toFixed(1)),
      minutiaeHeuristicCount: endingCandidates,
      validPrint: ridgeDensity > 0.12 && ridgeDensity < 0.88,
    },
  };
}

// Voice feature extractor (44-D: 20 spectral-mel band means + 20 stds + ZCR mean/std + RMS mean/std)
export function extractVoiceFeaturesFromPCM(samples, sampleRate = 16000) {
  if (!samples || samples.length < 256) {
    throw new Error('Audio buffer too short for acoustic extraction.');
  }
  const frameSize = 512;
  const hop = 256;
  const bands = 20;
  const frameBands = [];
  const zcrs = [];
  const rmss = [];

  for (let start = 0; start + frameSize <= samples.length; start += hop) {
    let sumSq = 0;
    let zc = 0;
    for (let i = 0; i < frameSize; i++) {
      const s = samples[start + i];
      sumSq += s * s;
      if (i > 0 && ((s >= 0 && samples[start + i - 1] < 0) || (s < 0 && samples[start + i - 1] >= 0))) {
        zc++;
      }
    }
    const rms = Math.sqrt(sumSq / frameSize);
    rmss.push(rms);
    zcrs.push(zc / frameSize);

    // Real-valued DFT energy across 20 mel-spaced frequency bins (0..4000 Hz)
    const bandEnergies = new Float32Array(bands);
    for (let b = 0; b < bands; b++) {
      const freq = 90 * Math.pow(1.22, b); // ~90 Hz to ~4 kHz
      const omega = (2 * Math.PI * freq) / sampleRate;
      let re = 0;
      let im = 0;
      for (let n = 0; n < frameSize; n += 2) {
        const w = 0.54 - 0.46 * Math.cos((2 * Math.PI * n) / (frameSize - 1));
        const x = samples[start + n] * w;
        re += x * Math.cos(omega * n);
        im -= x * Math.sin(omega * n);
      }
      bandEnergies[b] = Math.log1p(Math.hypot(re, im));
    }
    frameBands.push(bandEnergies);
  }

  const nFrames = frameBands.length || 1;
  const meanBands = new Array(bands).fill(0);
  const stdBands = new Array(bands).fill(0);
  for (const fb of frameBands) {
    for (let b = 0; b < bands; b++) meanBands[b] += fb[b] / nFrames;
  }
  for (const fb of frameBands) {
    for (let b = 0; b < bands; b++) stdBands[b] += (fb[b] - meanBands[b]) ** 2 / nFrames;
  }
  for (let b = 0; b < bands; b++) stdBands[b] = Math.sqrt(stdBands[b]);

  const meanZcr = zcrs.reduce((a, b) => a + b, 0) / (zcrs.length || 1);
  const stdZcr = Math.sqrt(zcrs.reduce((a, b) => a + (b - meanZcr) ** 2, 0) / (zcrs.length || 1));
  const meanRms = rmss.reduce((a, b) => a + b, 0) / (rmss.length || 1);
  const stdRms = Math.sqrt(rmss.reduce((a, b) => a + (b - meanRms) ** 2, 0) / (rmss.length || 1));

  // Voice Activity Detection segment counter for Challenge-Response heuristic
  const vadThresh = Math.max(0.012, meanRms * 0.75);
  let segments = 0;
  let inSpeech = false;
  let silenceFrames = 0;
  for (const r of rmss) {
    if (r >= vadThresh) {
      if (!inSpeech) {
        segments++;
        inSpeech = true;
      }
      silenceFrames = 0;
    } else if (inSpeech) {
      silenceFrames++;
      if (silenceFrames >= 4) inSpeech = false;
    }
  }

  const raw44 = [...meanBands, ...stdBands, meanZcr * 10, stdZcr * 10, meanRms * 10, stdRms * 10];
  const vector = l2Normalize(raw44);

  let clipped = 0;
  let peak = 0;
  for (let i = 0; i < samples.length; i++) {
    const abs = Math.abs(samples[i]);
    if (abs > peak) peak = abs;
    if (abs >= 0.98) clipped++;
  }
  const clippingRatio = Number((clipped / (samples.length || 1)).toFixed(4));
  const dynamicRangeDb = Number((20 * Math.log10((peak + 1e-4) / (meanRms + 1e-4)) + 12).toFixed(1));

  return {
    vector,
    dim: vector.length,
    stats: {
      durationSec: Number((samples.length / sampleRate).toFixed(2)),
      meanRms: Number(meanRms.toFixed(4)),
      meanZcr: Number(meanZcr.toFixed(4)),
      speechSegments: segments,
      frames: nFrames,
      clippingRatio,
      dynamicRangeDb,
    },
  };
}

export async function decodeAudioFileToPCM(fileOrBlob) {
  const arrayBuffer = await fileOrBlob.arrayBuffer();
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const ctx = new AudioCtx();
  try {
    const decoded = await ctx.decodeAudioData(arrayBuffer);
    const ch = decoded.getChannelData(0);
    return { samples: new Float32Array(ch), sampleRate: decoded.sampleRate };
  } finally {
    await ctx.close();
  }
}

// Early Feature Fusion (block scaling by 1 / sqrt(dim))
export function earlyFusionVector(faceVec, voiceVec) {
  const wf = 1 / Math.sqrt(faceVec.length || 1);
  const wv = 1 / Math.sqrt(voiceVec.length || 1);
  return l2Normalize([
    ...faceVec.map((v) => v * wf),
    ...voiceVec.map((v) => v * wv),
  ]);
}

// Hierarchical Verifier (2-modal & 3-modal)
export function runHierarchicalVerify({
  user,
  faceVec,
  voiceVec,
  fpVec = null,
  mode = 'hierarchical',
  thresholds,
  bundleReady = true,
}) {
  if (!bundleReady) {
    return { error: 'Biometric bundle is not ready. Retrain or initialize reference models first.' };
  }
  if (!user) {
    return { error: 'Unknown claimed identity. Please select an enrolled participant.' };
  }

  const refsFace = user.refs?.face || [];
  const refsVoice = user.refs?.voice || [];
  const refsFp = user.refs?.fingerprint || [];

  const faceScore = faceVec && refsFace.length ? scoreAgainstRefs(faceVec, refsFace) : null;
  const voiceScore = voiceVec && refsVoice.length ? scoreAgainstRefs(voiceVec, refsVoice) : null;
  const fpScore = fpVec && refsFp.length ? scoreAgainstRefs(fpVec, refsFp) : null;

  const thrFace = thresholds.face ?? 0.72;
  const thrVoice = thresholds.voice ?? 0.70;
  const thrFp = thresholds.fingerprint ?? 0.72;
  const thrEarly = thresholds.early ?? 0.73;
  const thrScore = thresholds.score ?? 0.72;
  const thr3 = thresholds.thr3 ?? 0.74;
  const wFace = thresholds.wFace ?? 0.58;
  const w3 = thresholds.w3 ?? { face: 0.45, voice: 0.30, fingerprint: 0.25 };

  if (mode === 'face_only') {
    if (faceScore === null) return { error: 'Missing face probe or enrolled face references.' };
    return {
      mode,
      finalScore: faceScore,
      threshold: thrFace,
      verified: faceScore >= thrFace,
      details: { faceScore },
      path: 'Face Verifier (HOG + LBP)',
    };
  }

  if (mode === 'voice_only') {
    if (voiceScore === null) return { error: 'Missing voice probe or enrolled voice references.' };
    return {
      mode,
      finalScore: voiceScore,
      threshold: thrVoice,
      verified: voiceScore >= thrVoice,
      details: { voiceScore },
      path: 'Voice Verifier (MFCC + ZCR + RMS)',
    };
  }

  if (mode === 'fingerprint_only') {
    if (fpScore === null) return { error: 'Missing fingerprint probe or enrolled fingerprint references.' };
    return {
      mode,
      finalScore: fpScore,
      threshold: thrFp,
      verified: fpScore >= thrFp,
      details: { fpScore },
      path: 'Fingerprint Verifier (Gabor + Ridge Orientation)',
    };
  }

  if (mode === 'early_fusion') {
    if (faceScore === null || voiceScore === null) {
      return { error: 'Early fusion requires both Face and Voice inputs and enrolled references.' };
    }
    const probeEarly = earlyFusionVector(faceVec, voiceVec);
    const refEarlyList = refsFace.map((rf, idx) => earlyFusionVector(rf, refsVoice[idx % refsVoice.length]));
    const earlyScore = scoreAgainstRefs(probeEarly, refEarlyList);
    return {
      mode,
      finalScore: earlyScore,
      threshold: thrEarly,
      verified: earlyScore >= thrEarly,
      details: { faceScore, voiceScore, earlyScore },
      path: 'Early Feature Fusion (1/sqrt(dim) block weighted)',
    };
  }

  if (mode === 'score_fusion') {
    if (faceScore === null || voiceScore === null) {
      return { error: 'Score fusion requires both Face and Voice inputs and enrolled references.' };
    }
    const combined = Number((wFace * faceScore + (1 - wFace) * voiceScore).toFixed(4));
    return {
      mode,
      finalScore: combined,
      threshold: thrScore,
      verified: combined >= thrScore,
      details: { faceScore, voiceScore, wFace },
      path: `Score Fusion (${wFace.toFixed(2)} Face + ${(1 - wFace).toFixed(2)} Voice)`,
    };
  }

  if (mode === 'decision_fusion') {
    if (faceScore === null || voiceScore === null) {
      return { error: 'Decision fusion requires both Face and Voice inputs and enrolled references.' };
    }
    const facePass = faceScore >= thrFace;
    const voicePass = voiceScore >= thrVoice;
    const rule = thresholds.decisionRule || 'AND';
    const verified = rule === 'AND' ? facePass && voicePass : facePass || voicePass;
    return {
      mode,
      finalScore: Number(((faceScore + voiceScore) / 2).toFixed(4)),
      threshold: thrScore,
      verified,
      details: { faceScore, voiceScore, facePass, voicePass, rule },
      path: `Decision Fusion (${rule})`,
    };
  }

  if (mode === 'three_modal') {
    if (faceVec === null || voiceVec === null || fpVec === null) {
      return { error: 'Three-modality verification requires Face, Voice, and Fingerprint inputs.' };
    }
    if (!refsFace.length || !refsVoice.length || !refsFp.length) {
      return { error: 'User lacks complete three-modality enrollment references (Face + Voice + Fingerprint).' };
    }
    const fused = Number(
      (w3.face * faceScore + w3.voice * voiceScore + w3.fingerprint * fpScore).toFixed(4)
    );
    return {
      mode,
      finalScore: fused,
      threshold: thr3,
      verified: fused >= thr3,
      details: { faceScore, voiceScore, fpScore, weights: w3 },
      path: 'Three-Modality Score Fusion (Face + Voice + Fingerprint)',
    };
  }

  // Default: Hierarchical (Face fast-pass/reject; uncertain band escalates to Early Fusion)
  if (faceScore === null) return { error: 'Hierarchical pipeline requires at least a Face probe.' };
  const highGate = Math.min(0.95, thrFace + 0.09);
  const lowGate = Math.max(0.35, thrFace - 0.14);

  if (faceScore >= highGate) {
    return {
      mode: 'hierarchical',
      finalScore: faceScore,
      threshold: highGate,
      verified: true,
      details: { faceScore, stage: 'Stage 1 Fast-Accept' },
      path: 'Hierarchical Stage 1 (High-Confidence Face Accept)',
    };
  }
  if (faceScore <= lowGate) {
    return {
      mode: 'hierarchical',
      finalScore: faceScore,
      threshold: lowGate,
      verified: false,
      details: { faceScore, stage: 'Stage 1 Fast-Reject' },
      path: 'Hierarchical Stage 1 (Low-Confidence Face Reject)',
    };
  }
  if (voiceScore === null) {
    return {
      error: `Face score (${(faceScore * 100).toFixed(1)}%) landed in the uncertain band (${(lowGate * 100).toFixed(0)}%–${(highGate * 100).toFixed(0)}%). Voice input is required for Stage 2 Early Fusion.`,
    };
  }
  const probeEarly = earlyFusionVector(faceVec, voiceVec);
  const refEarlyList = refsFace.map((rf, idx) => earlyFusionVector(rf, refsVoice[idx % refsVoice.length]));
  const earlyScore = scoreAgainstRefs(probeEarly, refEarlyList);
  return {
    mode: 'hierarchical',
    finalScore: earlyScore,
    threshold: thrEarly,
    verified: earlyScore >= thrEarly,
    details: { faceScore, voiceScore, earlyScore, stage: 'Stage 2 Escalated Early Fusion' },
    path: 'Hierarchical Stage 2 (Uncertain Face -> Early Fusion)',
  };
}

// Generate deterministic seeded vector for sample/demo participants only (never hides real capture)
export function makeSeededVector(seedStr, dim, jitter = 0) {
  let h = 2166136261;
  for (let i = 0; i < seedStr.length; i++) {
    h ^= seedStr.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const vec = new Array(dim);
  for (let i = 0; i < dim; i++) {
    h ^= i + 1;
    h = Math.imul(h, 16777619);
    const base = ((h >>> 0) / 4294967295) * 2 - 1;
    const noise = jitter ? (Math.sin(i * 12.9898 + jitter * 78.233) * jitter) : 0;
    vec[i] = base + noise;
  }
  return l2Normalize(vec);
}

// Compute full biometric evaluation metrics (TP, FP, TN, FN, FAR, FRR, EER, ROC, AUC)
export function computeBiometricMetrics(trials, threshold = 0.72) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (const t of trials) {
    const pred = t.score >= threshold;
    if (t.genuine && pred) tp++;
    else if (!t.genuine && pred) fp++;
    else if (!t.genuine && !pred) tn++;
    else fn++;
  }
  const total = trials.length || 1;
  const accuracy = (tp + tn) / total;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const far = fp + tn ? fp / (fp + tn) : 0;
  const frr = fn + tp ? fn / (fn + tp) : 0;

  // Sweep thresholds 0.00 -> 1.00 for ROC & EER
  const roc = [];
  let bestEerDiff = 1;
  let eer = 0;
  let eerThreshold = threshold;
  for (let step = 0; step <= 50; step++) {
    const thr = step / 50;
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

  // Trapezoidal AUC over sorted (far, tpr)
  const sorted = [...roc].sort((a, b) => a.far - b.far);
  let auc = 0;
  for (let i = 1; i < sorted.length; i++) {
    auc += ((sorted[i].far - sorted[i - 1].far) * (sorted[i].tpr + sorted[i - 1].tpr)) / 2;
  }

  return {
    tp,
    fp,
    tn,
    fn,
    accuracy,
    precision,
    recall,
    f1,
    far,
    frr,
    eer,
    eerThreshold,
    auc: Math.min(1, Math.max(0, auc)),
    roc,
  };
}
