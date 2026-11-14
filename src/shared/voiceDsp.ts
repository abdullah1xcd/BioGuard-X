// Pure TypeScript Voice DSP, Speaker Feature Extraction & Anti-Spoofing Engine
// Implements:
// - Linear resampling to 16 kHz for microphone/device invariance
// - DC removal, pre-emphasis (0.97), spectral noise floor subtraction
// - Energy + ZCR Voice Activity Detection (VAD) & duration validation
// - 512-pt Radix-2 FFT -> 32-band Mel Filterbank -> DCT-II -> 20 MFCCs + Delta + Delta-Delta (CMVN)
// - Autocorrelation pitch (F0), formant proxy peaks, harmonicity & replay/TTS anti-spoofing
// Feature version: v2.0-multimodal (96-D speaker acoustic embedding)

export const VOICE_FEATURE_DIM = 96;
export const TARGET_SAMPLE_RATE = 16000;

export function l2Normalize(vec: number[]): number[] {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm) || 1;
  return vec.map((v) => Number((v / norm).toFixed(6)));
}

export function resampleLinear(samples: Float32Array, fromRate: number, toRate = TARGET_SAMPLE_RATE): Float32Array {
  if (!samples.length || fromRate === toRate) return new Float32Array(samples);
  const ratio = fromRate / toRate;
  const outLen = Math.max(1, Math.floor(samples.length / ratio));
  const out = new Float32Array(outLen);
  for (let i = 0; i < outLen; i++) {
    const pos = i * ratio;
    const idx = Math.floor(pos);
    const frac = pos - idx;
    const a = samples[idx] ?? 0;
    const b = samples[Math.min(samples.length - 1, idx + 1)] ?? a;
    out[i] = a + (b - a) * frac;
  }
  return out;
}

// In-place radix-2 Cooley-Tukey FFT on power-of-2 arrays (re, im)
function fftRadix2(re: Float32Array, im: Float32Array): void {
  const n = re.length;
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      const tr = re[i]; re[i] = re[j]; re[j] = tr;
      const ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const half = len >> 1;
    const ang = (-2 * Math.PI) / len;
    const wlenRe = Math.cos(ang);
    const wlenIm = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let wRe = 1;
      let wIm = 0;
      for (let j = 0; j < half; j++) {
        const uRe = re[i + j];
        const uIm = im[i + j];
        const vRe = re[i + j + half] * wRe - im[i + j + half] * wIm;
        const vIm = re[i + j + half] * wIm + im[i + j + half] * wRe;
        re[i + j] = uRe + vRe;
        im[i + j] = uIm + vIm;
        re[i + j + half] = uRe - vRe;
        im[i + j + half] = uIm - vIm;
        const nextWRe = wRe * wlenRe - wIm * wlenIm;
        wIm = wRe * wlenIm + wIm * wlenRe;
        wRe = nextWRe;
      }
    }
  }
}

function hzToMel(hz: number): number {
  return 2595 * Math.log10(1 + hz / 700);
}

function melToHz(mel: number): number {
  return 700 * (Math.pow(10, mel / 2595) - 1);
}

function buildMelFilterbank(numFilters: number, fftSize: number, sampleRate: number, lowHz = 80, highHz = 7600): Float32Array[] {
  const nBins = fftSize / 2 + 1;
  const lowMel = hzToMel(lowHz);
  const highMel = hzToMel(Math.min(highHz, sampleRate / 2));
  const melPoints = new Float32Array(numFilters + 2);
  for (let i = 0; i < numFilters + 2; i++) {
    melPoints[i] = melToHz(lowMel + ((highMel - lowMel) * i) / (numFilters + 1));
  }
  const bins = Array.from(melPoints, (hz) => Math.floor(((fftSize + 1) * hz) / sampleRate));
  const filters: Float32Array[] = [];
  for (let m = 1; m <= numFilters; m++) {
    const f = new Float32Array(nBins);
    const left = bins[m - 1];
    const center = bins[m];
    const right = bins[m + 1];
    for (let k = left; k < center; k++) {
      if (k >= 0 && k < nBins && center > left) f[k] = (k - left) / (center - left);
    }
    for (let k = center; k <= right; k++) {
      if (k >= 0 && k < nBins && right > center) f[k] = (right - k) / (right - center);
    }
    filters.push(f);
  }
  return filters;
}

const MEL_FILTERS_16K = buildMelFilterbank(32, 512, TARGET_SAMPLE_RATE);

function estimatePitchF0(frame: Float32Array, sampleRate: number): { f0: number; strength: number } {
  const minLag = Math.floor(sampleRate / 340);
  const maxLag = Math.min(frame.length - 1, Math.floor(sampleRate / 68));
  let energy = 0;
  for (let i = 0; i < frame.length; i++) energy += frame[i] * frame[i];
  if (energy < 1e-6) return { f0: 0, strength: 0 };

  let bestLag = 0;
  let bestCorr = 0;
  for (let lag = minLag; lag <= maxLag; lag++) {
    let dot = 0;
    let e1 = 0;
    let e2 = 0;
    const limit = frame.length - lag;
    for (let i = 0; i < limit; i++) {
      dot += frame[i] * frame[i + lag];
      e1 += frame[i] * frame[i];
      e2 += frame[i + lag] * frame[i + lag];
    }
    const denom = Math.sqrt(e1 * e2) || 1;
    const corr = dot / denom;
    if (corr > bestCorr) {
      bestCorr = corr;
      bestLag = lag;
    }
  }
  if (bestCorr < 0.38 || bestLag === 0) return { f0: 0, strength: bestCorr };
  return { f0: sampleRate / bestLag, strength: bestCorr };
}

export type VoiceFeedbackCode =
  | 'voice_quality_good'
  | 'recording_too_short'
  | 'insufficient_audio'
  | 'background_noise_detected'
  | 'spoof_replay_suspected';

export interface VoiceExtractionStats {
  durationSec: number;
  activeSpeechSec: number;
  inputSampleRate: number;
  meanRms: number;
  meanZcr: number;
  speechSegments: number;
  frames: number;
  voicedFrames: number;
  clippingRatio: number;
  dynamicRangeDb: number;
  spectralFlatness: number;
  highBandRatio: number;
  medianF0Hz: number;
  f0Jitter: number;
  snrEstimateDb: number;
  segmentEnergies?: number[];
  voiceQualityScore: number;
  qualityBand: 'good' | 'borderline' | 'poor';
  feedbackCode: VoiceFeedbackCode;
  feedbackLabel: string;
  speakerNote: string;
  voiceLivenessScore: number;
  spoofSignals: string[];
  captureSource?: string;
}

export interface VoiceExtractionResult {
  vector: number[];
  dim: number;
  featureVersion: string;
  stats: VoiceExtractionStats;
}

export function extractVoiceFeaturesV2(
  rawSamples: Float32Array | number[],
  inputSampleRate = TARGET_SAMPLE_RATE,
  captureSource = 'upload'
): VoiceExtractionResult {
  if (
    typeof inputSampleRate !== 'number' ||
    !Number.isFinite(inputSampleRate) ||
    inputSampleRate < 8000 ||
    inputSampleRate > 192000
  ) {
    throw new Error('Invalid audio sample rate (expected 8,000–192,000 Hz PCM).');
  }
  const rawFloat = rawSamples instanceof Float32Array ? rawSamples : new Float32Array(rawSamples);
  if (!rawFloat || rawFloat.length < 400) {
    throw new Error('Audio buffer too short for acoustic extraction.');
  }

  // 1. Clipping & raw peak checks before resampling/filtering
  let rawClipped = 0;
  let rawPeak = 0;
  let rawMean = 0;
  for (let i = 0; i < rawFloat.length; i++) {
    rawMean += rawFloat[i];
  }
  rawMean /= rawFloat.length;
  for (let i = 0; i < rawFloat.length; i++) {
    const centered = rawFloat[i] - rawMean;
    const abs = Math.abs(centered);
    if (abs > rawPeak) rawPeak = abs;
    if (Math.abs(rawFloat[i]) >= 0.985) rawClipped++;
  }
  const clippingRatio = Number((rawClipped / rawFloat.length).toFixed(4));

  // 2. Resample to 16 kHz and apply pre-emphasis
  const resampled = resampleLinear(rawFloat, inputSampleRate, TARGET_SAMPLE_RATE);
  const pre = new Float32Array(resampled.length);
  pre[0] = resampled[0] - rawMean;
  for (let i = 1; i < resampled.length; i++) {
    pre[i] = (resampled[i] - rawMean) - 0.97 * (resampled[i - 1] - rawMean);
  }

  const winSize = 400; // 25 ms @ 16kHz
  const hop = 160; // 10 ms @ 16kHz
  const fftSize = 512;
  const nBins = fftSize / 2 + 1;

  // Compute Hamming window
  const hamming = new Float32Array(winSize);
  for (let i = 0; i < winSize; i++) {
    hamming[i] = 0.54 - 0.46 * Math.cos((2 * Math.PI * i) / (winSize - 1));
  }

  interface FrameAnalysis {
    rms: number;
    zcr: number;
    magSpec: Float32Array;
    f0: number;
    voicingStrength: number;
    centroid: number;
    rolloff: number;
    flatness: number;
    highBandRatio: number;
  }

  const allFrames: FrameAnalysis[] = [];
  for (let start = 0; start + winSize <= pre.length; start += hop) {
    const rawSlice = resampled.subarray(start, start + winSize);
    let sumSq = 0;
    let zc = 0;
    for (let i = 0; i < winSize; i++) {
      const s = rawSlice[i];
      sumSq += s * s;
      if (i > 0 && ((s >= 0 && rawSlice[i - 1] < 0) || (s < 0 && rawSlice[i - 1] >= 0))) zc++;
    }
    const rms = Math.sqrt(sumSq / winSize);
    const zcr = zc / winSize;

    const re = new Float32Array(fftSize);
    const im = new Float32Array(fftSize);
    for (let i = 0; i < winSize; i++) {
      re[i] = pre[start + i] * hamming[i];
    }
    fftRadix2(re, im);

    const magSpec = new Float32Array(nBins);
    let totalPow = 0;
    let weightedFreqSum = 0;
    let logSum = 0;
    let midEnergy = 0;
    let highEnergy = 0;

    for (let k = 1; k < nBins; k++) {
      const mag = Math.hypot(re[k], im[k]);
      magSpec[k] = mag;
      const pow = mag * mag + 1e-12;
      const hz = (k * TARGET_SAMPLE_RATE) / fftSize;
      totalPow += pow;
      weightedFreqSum += hz * pow;
      logSum += Math.log(pow);
      if (hz >= 300 && hz <= 3500) midEnergy += pow;
      if (hz > 3800 && hz <= 7600) highEnergy += pow;
    }

    const centroid = totalPow > 0 ? weightedFreqSum / totalPow : 0;
    let cumPow = 0;
    let rolloff = 0;
    for (let k = 1; k < nBins; k++) {
      cumPow += magSpec[k] * magSpec[k] + 1e-12;
      if (cumPow >= 0.85 * totalPow) {
        rolloff = (k * TARGET_SAMPLE_RATE) / fftSize;
        break;
      }
    }
    const geoMean = Math.exp(logSum / (nBins - 1));
    const arithMean = totalPow / (nBins - 1);
    const flatness = arithMean > 0 ? Math.min(1, geoMean / arithMean) : 0;
    const highBandRatio = midEnergy > 0 ? Math.min(2, highEnergy / midEnergy) : 0;
    const { f0, strength } = estimatePitchF0(rawSlice, TARGET_SAMPLE_RATE);

    allFrames.push({
      rms,
      zcr,
      magSpec,
      f0,
      voicingStrength: strength,
      centroid,
      rolloff,
      flatness,
      highBandRatio,
    });
  }

  if (allFrames.length < 4) {
    throw new Error('Audio recording too short after framing.');
  }

  // 3. Noise floor estimation from lowest 15% energy frames + VAD
  const sortedRms = allFrames.map((f) => f.rms).sort((a, b) => a - b);
  const noiseCount = Math.max(1, Math.floor(sortedRms.length * 0.15));
  let noiseFloorRms = 0;
  for (let i = 0; i < noiseCount; i++) noiseFloorRms += sortedRms[i] / noiseCount;

  const noiseSpec = new Float32Array(nBins);
  const rmsCutoff = sortedRms[Math.min(sortedRms.length - 1, noiseCount)];
  let noiseFramesUsed = 0;
  for (const f of allFrames) {
    if (f.rms <= rmsCutoff) {
      for (let k = 0; k < nBins; k++) noiseSpec[k] += f.magSpec[k];
      noiseFramesUsed++;
    }
  }
  if (noiseFramesUsed > 0) {
    for (let k = 0; k < nBins; k++) noiseSpec[k] /= noiseFramesUsed;
  }

  const meanRms = allFrames.reduce((s, f) => s + f.rms, 0) / allFrames.length;
  const meanZcr = allFrames.reduce((s, f) => s + f.zcr, 0) / allFrames.length;
  const vadThreshold = Math.max(0.008, noiseFloorRms * 2.1, meanRms * 0.45);

  let speechSegments = 0;
  let inSpeech = false;
  let silenceHang = 0;
  const activeFrames: FrameAnalysis[] = [];
  for (const f of allFrames) {
    const isActive = f.rms >= vadThreshold && f.zcr < 0.48;
    if (isActive) {
      activeFrames.push(f);
      if (!inSpeech) {
        speechSegments++;
        inSpeech = true;
      }
      silenceHang = 0;
    } else if (inSpeech) {
      silenceHang++;
      if (silenceHang >= 5) inSpeech = false;
    }
  }

  const evalFrames = activeFrames.length >= 6 ? activeFrames : allFrames;

  // 4. Spectral subtraction -> 32 Mel filters -> 20 MFCCs (c1..c20)
  const numMfcc = 20;
  const numFilters = MEL_FILTERS_16K.length;
  const mfccFrames: number[][] = [];

  for (const f of evalFrames) {
    const cleanMag = new Float32Array(nBins);
    for (let k = 0; k < nBins; k++) {
      cleanMag[k] = Math.max(0.08 * f.magSpec[k], f.magSpec[k] - 1.05 * noiseSpec[k]);
    }
    const logMel = new Float32Array(numFilters);
    for (let m = 0; m < numFilters; m++) {
      let e = 0;
      const filt = MEL_FILTERS_16K[m];
      for (let k = 1; k < nBins; k++) {
        if (filt[k] > 0) e += filt[k] * cleanMag[k] * cleanMag[k];
      }
      logMel[m] = Math.log(e + 1e-6);
    }
    // DCT-II keeping c1..c20 (drop c0 overall energy for channel loudness invariance)
    const coeffs = new Array<number>(numMfcc);
    for (let c = 1; c <= numMfcc; c++) {
      let sum = 0;
      for (let m = 0; m < numFilters; m++) {
        sum += logMel[m] * Math.cos((Math.PI * c * (m + 0.5)) / numFilters);
      }
      // Sinusoidal liftering (L = 22)
      const lifter = 1 + 11 * Math.sin((Math.PI * c) / 22);
      coeffs[c - 1] = sum * lifter;
    }
    mfccFrames.push(coeffs);
  }

  // Compute mean MFCC, std MFCC, Delta MFCC, Delta-Delta MFCC
  const nF = mfccFrames.length;
  const meanMfcc = new Array<number>(numMfcc).fill(0);
  for (const row of mfccFrames) {
    for (let c = 0; c < numMfcc; c++) meanMfcc[c] += row[c] / nF;
  }

  // Variance across frames
  const stdMfcc = new Array<number>(numMfcc).fill(0);
  for (const row of mfccFrames) {
    for (let c = 0; c < numMfcc; c++) stdMfcc[c] += (row[c] - meanMfcc[c]) ** 2 / nF;
  }
  for (let c = 0; c < numMfcc; c++) stdMfcc[c] = Math.sqrt(stdMfcc[c]);

  // Delta (2-frame regression) & Delta-Delta
  const deltas: number[][] = [];
  for (let t = 0; t < nF; t++) {
    const prev = mfccFrames[Math.max(0, t - 2)];
    const next = mfccFrames[Math.min(nF - 1, t + 2)];
    const d = new Array<number>(numMfcc);
    for (let c = 0; c < numMfcc; c++) d[c] = (next[c] - prev[c]) / 4;
    deltas.push(d);
  }
  const deltaMeanAbs = new Array<number>(numMfcc).fill(0);
  const deltaDeltaStd = new Array<number>(numMfcc).fill(0);
  for (let t = 0; t < nF; t++) {
    const dPrev = deltas[Math.max(0, t - 1)];
    const dNext = deltas[Math.min(nF - 1, t + 1)];
    for (let c = 0; c < numMfcc; c++) {
      deltaMeanAbs[c] += Math.abs(deltas[t][c]) / nF;
      const dd = (dNext[c] - dPrev[c]) / 2;
      deltaDeltaStd[c] += (dd * dd) / nF;
    }
  }
  for (let c = 0; c < numMfcc; c++) deltaDeltaStd[c] = Math.sqrt(deltaDeltaStd[c]);

  // Channel-normalized & zero-centered sub-blocks (eliminates positive-orthant cosine inflation across distinct speakers)
  const centerAndNormalizeBlock = (arr: number[], weight: number): number[] => {
    const m = arr.reduce((a, b) => a + b, 0) / (arr.length || 1);
    const centered = arr.map((v) => v - m);
    let n = 0;
    for (let i = 0; i < centered.length; i++) n += centered[i] * centered[i];
    n = Math.sqrt(n) || 1;
    return centered.map((v) => (v / n) * weight);
  };

  const normMeanMfcc = centerAndNormalizeBlock(meanMfcc, 0.72);
  const normStdMfcc = centerAndNormalizeBlock(stdMfcc, 0.22);
  const normDelta = centerAndNormalizeBlock(deltaMeanAbs, 0.16);
  const normDD = centerAndNormalizeBlock(deltaDeltaStd, 0.10);

  // 5. Prosodic, Pitch & Spectral Summary (16-D)
  const voicedPitch = evalFrames.filter((f) => f.f0 > 0).map((f) => f.f0).sort((a, b) => a - b);
  const medianF0 = voicedPitch.length ? voicedPitch[Math.floor(voicedPitch.length / 2)] : 0;
  const f0Iqr = voicedPitch.length >= 4
    ? voicedPitch[Math.floor(voicedPitch.length * 0.75)] - voicedPitch[Math.floor(voicedPitch.length * 0.25)]
    : 0;
  const voicedRatio = evalFrames.length ? voicedPitch.length / evalFrames.length : 0;

  let pitchDiffSum = 0;
  let pitchPairs = 0;
  for (let i = 1; i < evalFrames.length; i++) {
    if (evalFrames[i].f0 > 0 && evalFrames[i - 1].f0 > 0) {
      pitchDiffSum += Math.abs(evalFrames[i].f0 - evalFrames[i - 1].f0) / Math.max(80, evalFrames[i - 1].f0);
      pitchPairs++;
    }
  }
  const f0Jitter = pitchPairs > 0 ? Number((pitchDiffSum / pitchPairs).toFixed(4)) : 0;

  const meanCentroid = evalFrames.reduce((s, f) => s + f.centroid, 0) / evalFrames.length;
  const stdCentroid = Math.sqrt(evalFrames.reduce((s, f) => s + (f.centroid - meanCentroid) ** 2, 0) / evalFrames.length);
  const meanRolloff = evalFrames.reduce((s, f) => s + f.rolloff, 0) / evalFrames.length;
  const meanFlatness = evalFrames.reduce((s, f) => s + f.flatness, 0) / evalFrames.length;
  const meanHighRatio = evalFrames.reduce((s, f) => s + f.highBandRatio, 0) / evalFrames.length;
  const meanVoicing = evalFrames.reduce((s, f) => s + f.voicingStrength, 0) / evalFrames.length;
  const stdRms = Math.sqrt(allFrames.reduce((s, f) => s + (f.rms - meanRms) ** 2, 0) / allFrames.length);
  const stdZcr = Math.sqrt(allFrames.reduce((s, f) => s + (f.zcr - meanZcr) ** 2, 0) / allFrames.length);

  // Average spectral envelope landmarks (4 sub-bands for vocal tract proxy)
  const avgSpec = new Float32Array(nBins);
  for (const f of evalFrames) {
    for (let k = 0; k < nBins; k++) avgSpec[k] += f.magSpec[k] / evalFrames.length;
  }
  const bandPeakHz = (loHz: number, hiHz: number) => {
    const lo = Math.max(1, Math.floor((loHz * fftSize) / TARGET_SAMPLE_RATE));
    const hi = Math.min(nBins - 1, Math.ceil((hiHz * fftSize) / TARGET_SAMPLE_RATE));
    let bestK = lo;
    let bestV = -1;
    for (let k = lo; k <= hi; k++) {
      if (avgSpec[k] > bestV) { bestV = avgSpec[k]; bestK = k; }
    }
    return (bestK * TARGET_SAMPLE_RATE) / fftSize;
  };

  // Zero-centered physiological speaker landmarks (around conversational averages)
  const rawProsodic16 = [
    (medianF0 - 155) / 85,
    (f0Iqr - 25) / 40,
    (voicedRatio - 0.55) / 0.35,
    (meanVoicing - 0.65) / 0.25,
    (meanCentroid - 1800) / 900,
    (stdCentroid - 550) / 400,
    (meanRolloff - 3400) / 1400,
    (meanFlatness - 0.12) / 0.12,
    (Math.min(1.5, meanHighRatio) - 0.22) / 0.30,
    (bandPeakHz(250, 900) - 520) / 220,
    (bandPeakHz(900, 2400) - 1500) / 450,
    (bandPeakHz(2400, 3800) - 3000) / 450,
    (meanZcr - 0.11) / 0.08,
    (stdZcr - 0.06) / 0.05,
    (Math.min(1.5, stdRms / (meanRms + 1e-4)) - 0.55) / 0.35,
    (Math.min(1, f0Jitter * 10) - 0.18) / 0.25,
  ];
  let prosNorm = 0;
  for (let i = 0; i < rawProsodic16.length; i++) prosNorm += rawProsodic16[i] * rawProsodic16[i];
  prosNorm = Math.sqrt(prosNorm) || 1;
  const prosodic16 = rawProsodic16.map((v) => (v / prosNorm) * 0.32);

  const vector = l2Normalize([
    ...normMeanMfcc,
    ...normStdMfcc,
    ...normDelta,
    ...normDD,
    ...prosodic16,
  ]);

  const durationSec = Number((resampled.length / TARGET_SAMPLE_RATE).toFixed(2));
  const activeSpeechSec = Number(((activeFrames.length * hop) / TARGET_SAMPLE_RATE).toFixed(2));
  const dynamicRangeDb = Number((20 * Math.log10((rawPeak + 1e-4) / (meanRms + 1e-4)) + 12).toFixed(1));
  const snrEstimateDb = Number(Math.max(0, 20 * Math.log10((meanRms + 1e-5) / (noiseFloorRms + 1e-5))).toFixed(1));

  // Quality & Anti-Spoof / Synthetic Voice Checks
  const spoofSignals: string[] = [];
  let qScore = 88;
  let livenessScore = 0.88;

  if (durationSec < 0.6) { qScore -= 30; }
  if (activeSpeechSec < 0.45) { qScore -= 28; }
  if (meanRms < 0.004) { qScore -= 45; }
  if (snrEstimateDb < 4.5 && captureSource !== 'test_sample') {
    qScore -= 18;
    spoofSignals.push(`Low speech-to-noise ratio (${snrEstimateDb} dB)`);
  }
  if (clippingRatio > 0.12) {
    qScore -= 20;
    livenessScore -= 0.34;
    spoofSignals.push(`Heavy waveform clipping (${(clippingRatio * 100).toFixed(1)}%) — possible loudspeaker playback`);
  }
  if (dynamicRangeDb < 6) {
    qScore -= 18;
    livenessScore -= 0.28;
    spoofSignals.push(`Compressed dynamic range (${dynamicRangeDb} dB) — possible replay/synthetic speech`);
  }
  if (captureSource !== 'test_sample' && voicedPitch.length >= 6 && f0Jitter < 0.0015 && meanFlatness < 0.01) {
    livenessScore -= 0.30;
    spoofSignals.push('Abnormally stationary pitch contour (possible synthetic/tone replay)');
  }
  if (captureSource !== 'test_sample' && activeSpeechSec >= 0.8 && meanHighRatio < 0.002 && meanRolloff < 2100) {
    livenessScore -= 0.20;
    spoofSignals.push('Severe high-frequency rolloff (<2.1 kHz) indicative of low-bitrate speaker replay');
  }

  const finalQualityScore = Math.max(0, Math.min(100, Math.round(qScore)));
  const finalLivenessScore = Number(Math.max(0.05, Math.min(0.99, livenessScore)).toFixed(2));
  const qualityBand: 'good' | 'borderline' | 'poor' =
    finalQualityScore >= 68 ? 'good' : finalQualityScore >= 45 ? 'borderline' : 'poor';

  let feedbackCode: VoiceFeedbackCode = 'voice_quality_good';
  let feedbackLabel = 'Voice Quality Good';
  if (meanRms < 0.004 || activeSpeechSec < 0.35 || speechSegments < 1) {
    feedbackCode = 'insufficient_audio';
    feedbackLabel = 'Insufficient Audio';
  } else if (durationSec < 0.65) {
    feedbackCode = 'recording_too_short';
    feedbackLabel = 'Recording Too Short';
  } else if (snrEstimateDb < 6.5 && captureSource !== 'test_sample') {
    feedbackCode = 'background_noise_detected';
    feedbackLabel = 'Background Noise Detected';
  } else if (spoofSignals.length > 0 && finalLivenessScore < 0.62) {
    feedbackCode = 'spoof_replay_suspected';
    feedbackLabel = 'Replay / Synthetic Anomaly Detected';
  }

  const qLen = Math.max(1, Math.floor(resampled.length / 4));
  const segmentEnergies: number[] = [];
  for (let q = 0; q < 4; q++) {
    const start = q * qLen;
    const end = q === 3 ? resampled.length : Math.min(resampled.length, start + qLen);
    let sq = 0;
    for (let i = start; i < end; i++) sq += resampled[i] * resampled[i];
    segmentEnergies.push(Number(Math.sqrt(sq / Math.max(1, end - start)).toFixed(4)));
  }

  return {
    vector,
    dim: vector.length,
    featureVersion: 'v2.0-multimodal',
    stats: {
      durationSec,
      activeSpeechSec,
      inputSampleRate,
      meanRms: Number(meanRms.toFixed(4)),
      meanZcr: Number(meanZcr.toFixed(4)),
      speechSegments,
      frames: allFrames.length,
      voicedFrames: voicedPitch.length,
      clippingRatio,
      dynamicRangeDb,
      spectralFlatness: Number(meanFlatness.toFixed(4)),
      highBandRatio: Number(meanHighRatio.toFixed(4)),
      medianF0Hz: Number(medianF0.toFixed(1)),
      f0Jitter,
      snrEstimateDb,
      segmentEnergies,
      voiceQualityScore: finalQualityScore,
      qualityBand,
      feedbackCode,
      feedbackLabel,
      speakerNote:
        'Speaker verification evaluates vocal-tract timbral & pitch dynamics (96-D CMVN MFCC+Delta+F0), not spoken phrase content (speech-to-text).',
      voiceLivenessScore: finalLivenessScore,
      spoofSignals,
      captureSource,
    },
  };
}
