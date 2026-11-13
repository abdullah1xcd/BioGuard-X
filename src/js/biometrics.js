// Unified Client Biometric Extractor Bridge
// - Face: @vladmandic/human pretrained BlazeFace + FaceMesh + HSE-FaceRes (1024-D) + AntiSpoof/Liveness
// - Voice: Shared 16kHz-resampled CMVN 20-MFCC + Delta + Delta-Delta + F0/Formant DSP (96-D)
// - Fingerprint: Shared 128x128 Gabor Ridge Enhancement + Zhang-Suen Thinning + Minutiae Extractor
// - Statistics & Fusion: Re-exported cleanly from src/shared/ without duplicate verification code

import { extractVoiceFeaturesV2 } from '../shared/voiceDsp.ts';
import {
  extractFingerprintTemplateFromGray128,
  FP_SIZE,
} from '../shared/fingerprintEngine.ts';
import {
  computeClassificationMetrics,
  buildBiometricAnalyticsReport,
  wilsonCI95,
} from '../shared/metrics.ts';
import {
  extractPretrainedFaceFeatures,
  captureMultiFrameFaceFeatures,
  inspectLiveFaceGuidance,
  ensureFaceEngineReady,
  getFaceEngineStatus,
} from './faceEngine.js';

export {
  extractPretrainedFaceFeatures,
  captureMultiFrameFaceFeatures,
  inspectLiveFaceGuidance,
  ensureFaceEngineReady,
  getFaceEngineStatus,
  computeClassificationMetrics,
  buildBiometricAnalyticsReport,
  wilsonCI95,
};

// Re-export legacy helper name cleanly mapped to the rigorous ground-truth metric calculator
export function computeBiometricMetrics(trials, threshold = 0.72) {
  return computeClassificationMetrics(trials, threshold);
}

export function l2Normalize(vec) {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm) || 1;
  return vec.map((v) => v / norm);
}

// Convert Image / Video / Canvas into 128x128 grayscale Float32Array
export function sourceToGray(source, size = FP_SIZE) {
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, 0, 0, size, size);
  const { data } = ctx.getImageData(0, 0, size, size);
  const gray = new Float32Array(size * size);
  for (let i = 0; i < size * size; i++) {
    gray[i] = 0.299 * data[i * 4] + 0.587 * data[i * 4 + 1] + 0.114 * data[i * 4 + 2];
  }
  return { gray, size };
}

// Frame-to-frame motion score between live webcam frames (liveness check)
export function computeFrameMotion(sourceA, sourceB) {
  const { gray: gA } = sourceToGray(sourceA, 64);
  const { gray: gB } = sourceToGray(sourceB, 64);
  let diffSum = 0;
  for (let i = 0; i < gA.length; i++) {
    diffSum += Math.abs(gA[i] - gB[i]) / 255;
  }
  return Number((diffSum / gA.length).toFixed(4));
}

// Real Face Extraction via pretrained BlazeFace + FaceMesh + FaceRes 1024-D + AntiSpoof
export async function extractFaceFeatures(source, extraQuality = {}) {
  return extractPretrainedFaceFeatures(source, extraQuality);
}

// Real Voice Extraction via 16kHz CMVN MFCC + Delta + Delta-Delta + F0/Formant DSP (96-D)
export function extractVoiceFeaturesFromPCM(samples, sampleRate = 16000, captureSource = 'upload') {
  return extractVoiceFeaturesV2(samples, sampleRate, captureSource);
}

// Real Fingerprint Extraction via Gabor Ridge Enhancement + Thinning + Minutiae Template
export function extractFingerprintFeatures(source, captureSource = 'upload') {
  const w = source?.naturalWidth || source?.videoWidth || source?.width || 0;
  const h = source?.naturalHeight || source?.videoHeight || source?.height || 0;
  if (captureSource !== 'test_sample' && (w < 96 || h < 96)) {
    const err = new Error(
      `Poor Quality: Fingerprint image resolution too low (${w}×${h}px, minimum 96×96px required).`
    );
    err.code = 'low_fingerprint_resolution';
    err.qualityLabel = 'Poor Quality';
    throw err;
  }

  const { gray } = sourceToGray(source, FP_SIZE);
  const tpl = extractFingerprintTemplateFromGray128(gray);
  if (!tpl.validPrint && captureSource !== 'test_sample') {
    const err = new Error(
      `${tpl.qualityLabel}: Could not extract valid fingerprint template (minutiae=${tpl.minutiae.length}, coherence=${tpl.meanCoherence}, sharpness=${tpl.sharpness}, ridgeDensity=${tpl.ridgeDensity}%).`
    );
    err.code = 'invalid_fingerprint_image';
    err.template = tpl;
    err.qualityLabel = tpl.qualityLabel;
    throw err;
  }
  return {
    template: tpl,
    vector: tpl.descriptor128,
    dim: tpl.descriptor128.length,
    featureVersion: 'v2.0-multimodal',
    quality: {
      ridgeDensity: tpl.ridgeDensity,
      minutiaeHeuristicCount: tpl.minutiae.length,
      meanCoherence: tpl.meanCoherence,
      foregroundRatio: tpl.foregroundRatio,
      sharpness: tpl.sharpness,
      meanWavelengthPx: tpl.meanWavelengthPx,
      qualityScore: tpl.qualityScore,
      qualityLabel: tpl.qualityLabel,
      templateStatus: tpl.templateStatus,
      validPrint: tpl.validPrint,
      captureSource,
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

// Deterministic synthetic dev/test vector generator (EXPLICITLY tagged test_sample/test_impostor)
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
    const noise = jitter ? Math.sin(i * 12.9898 + jitter * 78.233) * jitter : 0;
    vec[i] = base + noise;
  }
  return l2Normalize(vec);
}
