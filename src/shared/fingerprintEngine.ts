// Pure TypeScript Fingerprint Ridge Enhancement, Thinning, Minutiae Extraction & Matching Engine
// Implements:
// - 128x128 foreground variance segmentation & contrast normalization
// - Blur/sharpness assessment + 3x3 Gaussian noise suppression before gradient estimation
// - Gradient-tensor local ridge orientation & coherence estimation
// - Per-block local ridge frequency estimation (oriented 1D ridge projection peak)
// - Frequency-adaptive & orientation-adaptive Gabor ridge enhancement
// - Local adaptive thresholding + morphological speckle/pinhole cleanup
// - Zhang-Suen morphological skeletonization (1-px ridges)
// - Rutovitz Crossing Number minutiae extraction + false-minutiae pruning (spurs, broken-ridge breaks, boundary)
// - Local 2-nearest-neighbor triangle descriptors + rotation/translation invariant RANSAC alignment
// - Honest 3-state matching decision: MATCH | NO MATCH | INCONCLUSIVE
// Feature version: v2.0-multimodal

export type FingerprintQualityLabel =
  | 'Good Quality'
  | 'Poor Quality'
  | 'Image Too Blurry'
  | 'Insufficient Ridge Details';

export type FingerprintDecision = 'MATCH' | 'NO MATCH' | 'INCONCLUSIVE';

export interface Minutia {
  x: number; // Normalized [0, 1]
  y: number; // Normalized [0, 1]
  theta: number; // Radians [0, 2*PI)
  type: 'ending' | 'bifurcation';
  quality: number; // [0, 1]
  // Local rotation-invariant triangle signature to two nearest neighbors:
  // [dist1, dist2, relAngle1Rad, relAngle2Rad]
  neighbors?: number[];
}

export interface FingerprintTemplate {
  version: string;
  descriptor128: number[]; // 4x4 grid x 8 orientation bins (L2-normalized)
  minutiae: Minutia[];
  ridgeDensity: number; // percentage 0..100
  meanCoherence: number; // 0..1
  foregroundRatio: number; // 0..1
  sharpness?: number;
  meanWavelengthPx?: number;
  qualityScore: number; // 0..100
  qualityLabel?: FingerprintQualityLabel;
  templateStatus?: 'Valid Minutiae Template' | 'Insufficient Features';
  validPrint: boolean;
}

export interface FingerprintMatchResult {
  score: number; // Calibrated [0, 1]
  matchedMinutiae: number;
  probeMinutiae: number;
  refMinutiae: number;
  orientationScore: number;
  estimatedRotationDeg: number;
  isPartialMatch: boolean;
  decision?: FingerprintDecision;
  decisionReason?: string;
}

export const FP_SIZE = 128;

function l2Norm(vec: number[]): number[] {
  let n = 0;
  for (let i = 0; i < vec.length; i++) n += vec[i] * vec[i];
  n = Math.sqrt(n) || 1;
  return vec.map((v) => Number((v / n).toFixed(6)));
}

function angleDiffRad(a: number, b: number): number {
  let d = Math.abs(a - b) % (2 * Math.PI);
  if (d > Math.PI) d = 2 * Math.PI - d;
  return d;
}

function axialAngleDiffRad(a: number, b: number): number {
  let d = Math.abs(a - b) % Math.PI;
  if (d > Math.PI / 2) d = Math.PI - d;
  return d;
}

export function extractFingerprintTemplateFromGray128(grayInput: Float32Array): FingerprintTemplate {
  const N = FP_SIZE;
  if (grayInput.length !== N * N) {
    throw new Error(`Expected ${N * N} grayscale pixels, got ${grayInput.length}.`);
  }

  // 0. Gentle 3x3 Gaussian denoise for sensor speckle stability (preserving ridge spacing >= 5px)
  const denoised = new Float32Array(N * N);
  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      if (y === 0 || x === 0 || y === N - 1 || x === N - 1) {
        denoised[y * N + x] = grayInput[y * N + x];
        continue;
      }
      const c =
        4 * grayInput[y * N + x] +
        2 * (grayInput[(y - 1) * N + x] + grayInput[(y + 1) * N + x] + grayInput[y * N + x - 1] + grayInput[y * N + x + 1]) +
        (grayInput[(y - 1) * N + x - 1] + grayInput[(y - 1) * N + x + 1] + grayInput[(y + 1) * N + x - 1] + grayInput[(y + 1) * N + x + 1]);
      denoised[y * N + x] = c / 16;
    }
  }

  // 1. Block-based foreground variance segmentation (8x8 blocks -> 16x16 grid)
  const block = 8;
  const gridN = N / block;
  const blockVar = new Float32Array(gridN * gridN);
  const blockMean = new Float32Array(gridN * gridN);
  for (let by = 0; by < gridN; by++) {
    for (let bx = 0; bx < gridN; bx++) {
      let sum = 0;
      for (let dy = 0; dy < block; dy++) {
        for (let dx = 0; dx < block; dx++) {
          sum += denoised[(by * block + dy) * N + (bx * block + dx)];
        }
      }
      const mean = sum / (block * block);
      blockMean[by * gridN + bx] = mean;
      let vSum = 0;
      for (let dy = 0; dy < block; dy++) {
        for (let dx = 0; dx < block; dx++) {
          const d = denoised[(by * block + dy) * N + (bx * block + dx)] - mean;
          vSum += d * d;
        }
      }
      blockVar[by * gridN + bx] = Math.sqrt(vSum / (block * block));
    }
  }

  const fgBlock = new Uint8Array(gridN * gridN);
  for (let i = 0; i < fgBlock.length; i++) {
    fgBlock[i] = blockVar[i] > 8.0 ? 1 : 0;
  }
  const fgClosed = new Uint8Array(fgBlock);
  for (let by = 1; by < gridN - 1; by++) {
    for (let bx = 1; bx < gridN - 1; bx++) {
      let neighbors = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          if (fgBlock[(by + dy) * gridN + (bx + dx)]) neighbors++;
        }
      }
      if (fgBlock[by * gridN + bx] === 0 && neighbors >= 6) fgClosed[by * gridN + bx] = 1;
      if (fgBlock[by * gridN + bx] === 1 && neighbors <= 2) fgClosed[by * gridN + bx] = 0;
    }
  }

  let fgBlocksCount = 0;
  const fgMask = new Uint8Array(N * N);
  for (let by = 0; by < gridN; by++) {
    for (let bx = 0; bx < gridN; bx++) {
      const isFg = fgClosed[by * gridN + bx];
      if (isFg) fgBlocksCount++;
      for (let dy = 0; dy < block; dy++) {
        for (let dx = 0; dx < block; dx++) {
          fgMask[(by * block + dy) * N + (bx * block + dx)] = isFg;
        }
      }
    }
  }
  const foregroundRatio = fgBlocksCount / (gridN * gridN);

  // Measure foreground Laplacian sharpness from raw input (blur assessment)
  let lapSqSum = 0;
  let lapCount = 0;
  for (let y = 2; y < N - 2; y++) {
    for (let x = 2; x < N - 2; x++) {
      const idx = y * N + x;
      if (!fgMask[idx]) continue;
      const lap = 4 * grayInput[idx] - grayInput[idx - 1] - grayInput[idx + 1] - grayInput[idx - N] - grayInput[idx + N];
      lapSqSum += lap * lap;
      lapCount++;
    }
  }
  const sharpness = lapCount > 0 ? Number(Math.sqrt(lapSqSum / lapCount).toFixed(1)) : 0;

  // 2. Local contrast normalization inside foreground
  const norm = new Float32Array(N * N);
  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      const by = Math.floor(y / block);
      const bx = Math.floor(x / block);
      const m = blockMean[by * gridN + bx];
      const s = Math.max(12, blockVar[by * gridN + bx]);
      const z = (denoised[y * N + x] - m) / s;
      norm[y * N + x] = Math.max(-2.5, Math.min(2.5, z));
    }
  }

  // 3. Sobel gradient tensor -> block ridge orientation & coherence
  const orient = new Float32Array(N * N);
  const coherenceField = new Float32Array(N * N);
  const gxArr = new Float32Array(N * N);
  const gyArr = new Float32Array(N * N);

  for (let y = 1; y < N - 1; y++) {
    for (let x = 1; x < N - 1; x++) {
      const idx = y * N + x;
      const gx =
        norm[(y - 1) * N + (x + 1)] + 2 * norm[y * N + (x + 1)] + norm[(y + 1) * N + (x + 1)] -
        norm[(y - 1) * N + (x - 1)] - 2 * norm[y * N + (x - 1)] - norm[(y + 1) * N + (x - 1)];
      const gy =
        norm[(y + 1) * N + (x - 1)] + 2 * norm[(y + 1) * N + x] + norm[(y + 1) * N + (x + 1)] -
        norm[(y - 1) * N + (x - 1)] - 2 * norm[(y - 1) * N + x] - norm[(y - 1) * N + (x + 1)];
      gxArr[idx] = gx;
      gyArr[idx] = gy;
    }
  }

  const orientHist = new Array<number>(4 * 4 * 8).fill(0);
  let cohSum = 0;
  let cohCount = 0;

  for (let y = 4; y < N - 4; y++) {
    for (let x = 4; x < N - 4; x++) {
      if (!fgMask[y * N + x]) continue;
      let jxx = 0;
      let jyy = 0;
      let jxy = 0;
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const gxi = gxArr[(y + dy) * N + (x + dx)];
          const gyi = gyArr[(y + dy) * N + (x + dx)];
          jxx += gxi * gxi;
          jyy += gyi * gyi;
          jxy += gxi * gyi;
        }
      }
      const gradAngle = 0.5 * Math.atan2(2 * jxy, jxx - jyy);
      let ridgeAngle = gradAngle + Math.PI / 2;
      if (ridgeAngle < 0) ridgeAngle += Math.PI;
      if (ridgeAngle >= Math.PI) ridgeAngle -= Math.PI;
      orient[y * N + x] = ridgeAngle;

      const denom = jxx + jyy + 1e-6;
      const coh = Math.sqrt((jxx - jyy) ** 2 + 4 * jxy * jxy) / denom;
      coherenceField[y * N + x] = coh;
      cohSum += coh;
      cohCount++;

      const bin = Math.min(7, Math.floor((ridgeAngle / Math.PI) * 8));
      const cy = Math.floor(y / 32);
      const cx = Math.floor(x / 32);
      orientHist[(cy * 4 + cx) * 8 + bin] += coh;
    }
  }
  const meanCoherence = cohCount > 0 ? cohSum / cohCount : 0;

  // 4. Local Ridge Frequency Estimation (oriented 1D ridge-valley X-signature projection)
  const blockWavelength = new Float32Array(gridN * gridN).fill(7.5);
  let wlSum = 0;
  let wlCount = 0;
  const sig = new Float32Array(21); // [-10..+10] perpendicular to ridge

  for (let by = 1; by < gridN - 1; by++) {
    for (let bx = 1; bx < gridN - 1; bx++) {
      if (!fgClosed[by * gridN + bx]) continue;
      const cy = by * block + 4;
      const cx = bx * block + 4;
      if (cy < 12 || cy >= N - 12 || cx < 12 || cx >= N - 12) continue;

      const theta = orient[cy * N + cx];
      const cosT = Math.cos(theta);
      const sinT = Math.sin(theta);

      for (let k = -10; k <= 10; k++) {
        let acc = 0;
        let cnt = 0;
        for (let u = -4; u <= 4; u++) {
          const sx = Math.round(cx + u * cosT - k * sinT);
          const sy = Math.round(cy + u * sinT + k * cosT);
          if (sx >= 0 && sx < N && sy >= 0 && sy < N) {
            acc += -norm[sy * N + sx];
            cnt++;
          }
        }
        sig[k + 10] = cnt > 0 ? acc / cnt : 0;
      }

      // Detect local peaks in 1D ridge signature
      const peaks: number[] = [];
      for (let k = 1; k < sig.length - 1; k++) {
        if (sig[k] > sig[k - 1] && sig[k] >= sig[k + 1] && sig[k] > 0.12) {
          peaks.push(k);
        }
      }
      if (peaks.length >= 2) {
        const avgDiff = (peaks[peaks.length - 1] - peaks[0]) / (peaks.length - 1);
        if (avgDiff >= 4.5 && avgDiff <= 13.5) {
          blockWavelength[by * gridN + bx] = avgDiff;
          wlSum += avgDiff;
          wlCount++;
        }
      }
    }
  }
  const globalWavelength = wlCount > 0 ? wlSum / wlCount : 7.5;
  // Smooth missing/noisy foreground block wavelengths using neighbor median/average
  const smoothedWl = new Float32Array(blockWavelength);
  for (let by = 1; by < gridN - 1; by++) {
    for (let bx = 1; bx < gridN - 1; bx++) {
      let s = 0;
      let c = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const idx = (by + dy) * gridN + (bx + dx);
          if (fgClosed[idx]) {
            s += blockWavelength[idx];
            c++;
          }
        }
      }
      smoothedWl[by * gridN + bx] = c > 0 ? s / c : globalWavelength;
    }
  }

  // 5. Frequency- & Orientation-Adaptive Gabor Ridge Enhancement
  const enhanced = new Float32Array(N * N);
  for (let y = 5; y < N - 5; y++) {
    for (let x = 5; x < N - 5; x++) {
      if (!fgMask[y * N + x]) continue;
      const theta = orient[y * N + x];
      const cosT = Math.cos(theta);
      const sinT = Math.sin(theta);
      const wl = smoothedWl[Math.floor(y / block) * gridN + Math.floor(x / block)] || 7.5;
      const ridgeFreq = 1 / wl;
      const sigma = Math.max(1.8, Math.min(3.6, wl * 0.36));
      let acc = 0;
      let wSum = 0;
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const xr = dx * cosT + dy * sinT;
          const yr = -dx * sinT + dy * cosT;
          const g = Math.exp(-(xr * xr + yr * yr) / (2 * sigma * sigma)) * Math.cos(2 * Math.PI * ridgeFreq * yr);
          acc += -norm[(y + dy) * N + (x + dx)] * g;
          wSum += Math.abs(g);
        }
      }
      enhanced[y * N + x] = wSum > 0 ? acc / wSum : 0;
    }
  }

  // 6. Adaptive Local Thresholding + Morphological Noise/Pinhole Cleanup
  const binRaw = new Uint8Array(N * N);
  for (let y = 5; y < N - 5; y++) {
    for (let x = 5; x < N - 5; x++) {
      const idx = y * N + x;
      if (!fgMask[idx]) continue;
      let localSum = 0;
      let localCnt = 0;
      for (let dy = -4; dy <= 4; dy += 2) {
        for (let dx = -4; dx <= 4; dx += 2) {
          const nIdx = (y + dy) * N + (x + dx);
          if (fgMask[nIdx]) {
            localSum += enhanced[nIdx];
            localCnt++;
          }
        }
      }
      const localMean = localCnt > 0 ? localSum / localCnt : 0;
      const thr = Math.max(0.025, localMean + 0.015);
      if (enhanced[idx] > thr) {
        binRaw[idx] = 1;
      }
    }
  }

  // Morphological cleanup: remove isolated 1-px speckles and fill isolated 1-px pinholes
  const bin = new Uint8Array(binRaw);
  let ridgePixels = 0;
  let fgPixels = 0;
  for (let y = 5; y < N - 5; y++) {
    for (let x = 5; x < N - 5; x++) {
      const idx = y * N + x;
      if (!fgMask[idx]) continue;
      fgPixels++;
      let nbOnes = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          if (dx === 0 && dy === 0) continue;
          if (binRaw[(y + dy) * N + (x + dx)]) nbOnes++;
        }
      }
      if (binRaw[idx] === 1 && nbOnes <= 1) bin[idx] = 0;
      else if (binRaw[idx] === 0 && nbOnes >= 7) bin[idx] = 1;
      if (bin[idx] === 1) ridgePixels++;
    }
  }
  const ridgeDensity = fgPixels > 0 ? (ridgePixels / fgPixels) * 100 : 0;

  // 7. Zhang-Suen Thinning -> 1-px skeleton
  const skel = new Uint8Array(bin);
  const toClear = new Uint8Array(N * N);
  for (let iter = 0; iter < 18; iter++) {
    let changed = false;
    for (let step = 0; step < 2; step++) {
      toClear.fill(0);
      for (let y = 1; y < N - 1; y++) {
        for (let x = 1; x < N - 1; x++) {
          const idx = y * N + x;
          if (skel[idx] !== 1) continue;
          const p2 = skel[(y - 1) * N + x];
          const p3 = skel[(y - 1) * N + x + 1];
          const p4 = skel[y * N + x + 1];
          const p5 = skel[(y + 1) * N + x + 1];
          const p6 = skel[(y + 1) * N + x];
          const p7 = skel[(y + 1) * N + x - 1];
          const p8 = skel[y * N + x - 1];
          const p9 = skel[(y - 1) * N + x - 1];

          const B = p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9;
          if (B < 2 || B > 6) continue;

          let A = 0;
          if (p2 === 0 && p3 === 1) A++;
          if (p3 === 0 && p4 === 1) A++;
          if (p4 === 0 && p5 === 1) A++;
          if (p5 === 0 && p6 === 1) A++;
          if (p6 === 0 && p7 === 1) A++;
          if (p7 === 0 && p8 === 1) A++;
          if (p8 === 0 && p9 === 1) A++;
          if (p9 === 0 && p2 === 1) A++;
          if (A !== 1) continue;

          if (step === 0) {
            if (p2 * p4 * p6 !== 0) continue;
            if (p4 * p6 * p8 !== 0) continue;
          } else {
            if (p2 * p4 * p8 !== 0) continue;
            if (p2 * p6 * p8 !== 0) continue;
          }
          toClear[idx] = 1;
          changed = true;
        }
      }
      for (let i = 0; i < skel.length; i++) {
        if (toClear[i]) skel[i] = 0;
      }
    }
    if (!changed) break;
  }

  // 8. Rutovitz Crossing Number minutiae extraction inside eroded foreground mask
  const rawMinutiae: Array<{ px: number; py: number; theta: number; type: 'ending' | 'bifurcation'; quality: number }> = [];
  const margin = 8;
  for (let y = margin; y < N - margin; y++) {
    for (let x = margin; x < N - margin; x++) {
      if (skel[y * N + x] !== 1) continue;
      if (!fgMask[(y - 6) * N + x] || !fgMask[(y + 6) * N + x] || !fgMask[y * N + (x - 6)] || !fgMask[y * N + (x + 6)]) {
        continue;
      }
      const nb = [
        skel[(y - 1) * N + x],
        skel[(y - 1) * N + x + 1],
        skel[y * N + x + 1],
        skel[(y + 1) * N + x + 1],
        skel[(y + 1) * N + x],
        skel[(y + 1) * N + x - 1],
        skel[y * N + x - 1],
        skel[(y - 1) * N + x - 1],
      ];
      let cn = 0;
      for (let k = 0; k < 8; k++) cn += Math.abs(nb[k] - nb[(k + 1) % 8]);
      cn = cn / 2;

      if (cn === 1 || cn === 3) {
        const type = cn === 1 ? 'ending' : 'bifurcation';
        let theta = orient[y * N + x];
        if (cn === 1) {
          const dxOpts = [0, 1, 1, 1, 0, -1, -1, -1];
          const dyOpts = [-1, -1, 0, 1, 1, 1, 0, -1];
          for (let k = 0; k < 8; k++) {
            if (nb[k] === 1) {
              const dot = Math.cos(theta) * dxOpts[k] + Math.sin(theta) * dyOpts[k];
              if (dot < 0) theta = (theta + Math.PI) % (2 * Math.PI);
              break;
            }
          }
        }
        const q = Number(Math.min(1, coherenceField[y * N + x] * 1.15).toFixed(3));
        if (q >= 0.25) {
          rawMinutiae.push({ px: x, py: y, theta, type, quality: q });
        }
      }
    }
  }

  // 9. False-minutiae pruning:
  // (a) Remove opposing broken-ridge endings (two endings <= 5.5px apart pointing nearly opposite)
  const suppressed = new Set<number>();
  for (let i = 0; i < rawMinutiae.length; i++) {
    if (rawMinutiae[i].type !== 'ending') continue;
    for (let j = i + 1; j < rawMinutiae.length; j++) {
      if (rawMinutiae[j].type !== 'ending') continue;
      const dist = Math.hypot(rawMinutiae[i].px - rawMinutiae[j].px, rawMinutiae[i].py - rawMinutiae[j].py);
      if (dist <= 5.5) {
        const aDiff = angleDiffRad(rawMinutiae[i].theta, rawMinutiae[j].theta);
        if (Math.abs(aDiff - Math.PI) < 0.72) {
          suppressed.add(i);
          suppressed.add(j);
        }
      }
    }
  }
  // (b) Remove short-spur ending + adjacent bifurcation pair (<= 4.5px apart)
  for (let i = 0; i < rawMinutiae.length; i++) {
    if (suppressed.has(i) || rawMinutiae[i].type !== 'ending') continue;
    for (let j = 0; j < rawMinutiae.length; j++) {
      if (i === j || suppressed.has(j) || rawMinutiae[j].type !== 'bifurcation') continue;
      const dist = Math.hypot(rawMinutiae[i].px - rawMinutiae[j].px, rawMinutiae[i].py - rawMinutiae[j].py);
      if (dist <= 4.5) {
        suppressed.add(i);
        suppressed.add(j);
        break;
      }
    }
  }

  const surviving = rawMinutiae.filter((_, idx) => !suppressed.has(idx));

  // (c) Enforce minimum 6px separation by quality order
  const pruned: typeof rawMinutiae = [];
  surviving.sort((a, b) => b.quality - a.quality);
  for (const m of surviving) {
    const tooClose = pruned.some((k) => Math.hypot(k.px - m.px, k.py - m.py) < 6.0);
    if (!tooClose) pruned.push(m);
    if (pruned.length >= 64) break;
  }

  // 10. Compute local 2-nearest-neighbor triangle signature per minutia
  const minutiae: Minutia[] = pruned.map((m, idx) => {
    const base: Minutia = {
      x: Number((m.px / N).toFixed(4)),
      y: Number((m.py / N).toFixed(4)),
      theta: Number(m.theta.toFixed(4)),
      type: m.type,
      quality: m.quality,
    };
    if (pruned.length >= 3) {
      const dists = pruned
        .map((other, oIdx) => ({
          oIdx,
          d: Math.hypot((other.px - m.px) / N, (other.py - m.py) / N),
          phi: Math.atan2(other.py - m.py, other.px - m.px) - m.theta,
        }))
        .filter((item) => item.oIdx !== idx)
        .sort((a, b) => a.d - b.d);
      const n1 = dists[0];
      const n2 = dists[1];
      const wrap = (a: number) => {
        let r = a % (2 * Math.PI);
        if (r < 0) r += 2 * Math.PI;
        return r;
      };
      base.neighbors = [
        Number(n1.d.toFixed(4)),
        Number(n2.d.toFixed(4)),
        Number(wrap(n1.phi).toFixed(3)),
        Number(wrap(n2.phi).toFixed(3)),
      ];
    }
    return base;
  });

  const validPrint =
    foregroundRatio >= 0.14 &&
    meanCoherence >= 0.28 &&
    ridgeDensity >= 14 &&
    ridgeDensity <= 82 &&
    minutiae.length >= 4 &&
    sharpness >= 3.2;

  const qualityScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(
        Math.min(1, meanCoherence / 0.72) * 40 +
          Math.min(1, minutiae.length / 22) * 30 +
          Math.min(1, foregroundRatio / 0.55) * 18 +
          Math.min(1, sharpness / 18) * 12
      )
    )
  );

  let qualityLabel: FingerprintQualityLabel = 'Good Quality';
  if (foregroundRatio > 0.08 && sharpness < 4.5 && meanCoherence < 0.36) {
    qualityLabel = 'Image Too Blurry';
  } else if (minutiae.length < 4 || meanCoherence < 0.28 || ridgeDensity < 14 || ridgeDensity > 82) {
    qualityLabel = 'Insufficient Ridge Details';
  } else if (!validPrint || qualityScore < 50) {
    qualityLabel = 'Poor Quality';
  }

  return {
    version: 'v2.0-multimodal',
    descriptor128: l2Norm(orientHist),
    minutiae,
    ridgeDensity: Number(ridgeDensity.toFixed(1)),
    meanCoherence: Number(meanCoherence.toFixed(3)),
    foregroundRatio: Number(foregroundRatio.toFixed(3)),
    sharpness,
    meanWavelengthPx: Number(globalWavelength.toFixed(2)),
    qualityScore,
    qualityLabel,
    templateStatus: validPrint ? 'Valid Minutiae Template' : 'Insufficient Features',
    validPrint,
  };
}

function localNeighborConsistency(pa: Minutia, ra: Minutia): number {
  if (!pa.neighbors || !ra.neighbors || pa.neighbors.length < 4 || ra.neighbors.length < 4) return 1.0;
  const dDiff1 = Math.abs(pa.neighbors[0] - ra.neighbors[0]);
  const dDiff2 = Math.abs(pa.neighbors[1] - ra.neighbors[1]);
  const aDiff1 = angleDiffRad(pa.neighbors[2], ra.neighbors[2]);
  const aDiff2 = angleDiffRad(pa.neighbors[3], ra.neighbors[3]);
  const distSim = Math.max(0.45, 1 - (dDiff1 + dDiff2) * 3.5);
  const angSim = Math.max(0.55, 1 - (aDiff1 + aDiff2) / (Math.PI * 1.4));
  return (distSim + angSim) / 2;
}

// Classify fingerprint result explicitly into MATCH | NO MATCH | INCONCLUSIVE
export function classifyFingerprintDecision(
  matchRes: FingerprintMatchResult,
  threshold = 0.72,
  probeQualityScore = 75,
  probeValidPrint = true
): { decision: FingerprintDecision; reason: string } {
  const minMinutiae = Math.min(matchRes.probeMinutiae, matchRes.refMinutiae);
  if (!probeValidPrint || probeQualityScore < 42 || matchRes.probeMinutiae < 4 || matchRes.refMinutiae < 4) {
    return {
      decision: 'INCONCLUSIVE',
      reason: 'Insufficient valid fingerprint ridge detail or capture quality to make a reliable determination.',
    };
  }
  const margin = Math.abs(matchRes.score - threshold);
  if (margin <= 0.035 && probeQualityScore < 65) {
    return {
      decision: 'INCONCLUSIVE',
      reason: `Fingerprint score (${(matchRes.score * 100).toFixed(1)}%) sits on borderline threshold (${(threshold * 100).toFixed(0)}%) with moderate image quality.`,
    };
  }
  if (matchRes.score >= threshold) {
    if (matchRes.matchedMinutiae < Math.min(4, minMinutiae)) {
      return {
        decision: 'INCONCLUSIVE',
        reason: `Global ridge flow aligned, but only ${matchRes.matchedMinutiae} minutiae correspondences were verified.`,
      };
    }
    return {
      decision: 'MATCH',
      reason: `${matchRes.matchedMinutiae}/${matchRes.probeMinutiae} minutiae matched above threshold (${(threshold * 100).toFixed(0)}%).`,
    };
  }
  return {
    decision: 'NO MATCH',
    reason: `Matched minutiae (${matchRes.matchedMinutiae}) and similarity (${(matchRes.score * 100).toFixed(1)}%) fell below ${(threshold * 100).toFixed(0)}% threshold.`,
  };
}

// Rotation & Translation Invariant Minutiae Matcher (RANSAC rigid transform alignment + star-neighborhood weighting)
export function matchFingerprintTemplates(
  probe: FingerprintTemplate,
  ref: FingerprintTemplate
): FingerprintMatchResult {
  const pMin = probe.minutiae || [];
  const rMin = ref.minutiae || [];
  const nP = pMin.length;
  const nR = rMin.length;

  let orientDot = 0;
  if (probe.descriptor128?.length === 128 && ref.descriptor128?.length === 128) {
    for (let i = 0; i < 128; i++) orientDot += probe.descriptor128[i] * ref.descriptor128[i];
  }
  const orientationScore = Math.max(0, Math.min(1, orientDot));

  if (nP < 4 || nR < 4) {
    return {
      score: Number((orientationScore * 0.55).toFixed(4)),
      matchedMinutiae: 0,
      probeMinutiae: nP,
      refMinutiae: nR,
      orientationScore: Number(orientationScore.toFixed(4)),
      estimatedRotationDeg: 0,
      isPartialMatch: false,
      decision: 'INCONCLUSIVE',
      decisionReason: 'Fewer than 4 minutiae extracted.',
    };
  }

  let bestMatchedWeighted = 0;
  let bestMatchedCount = 0;
  let bestDTheta = 0;

  const pAnchors = pMin.slice(0, 28);
  const rAnchors = rMin.slice(0, 28);
  const distTol = 0.088;
  const angleTol = (28 * Math.PI) / 180;

  for (const pa of pAnchors) {
    for (const ra of rAnchors) {
      if (pa.type !== ra.type) continue;
      const baseDTheta = ra.theta - pa.theta;
      const candidates = pa.type === 'bifurcation' ? [baseDTheta, baseDTheta + Math.PI] : [baseDTheta];

      for (const dtheta of candidates) {
        const cosT = Math.cos(dtheta);
        const sinT = Math.sin(dtheta);
        const usedRef = new Set<number>();
        let matchedCount = 0;
        let matchedWeighted = 0;

        for (let i = 0; i < nP; i++) {
          const pm = pMin[i];
          const dx0 = pm.x - pa.x;
          const dy0 = pm.y - pa.y;
          const tx = ra.x + dx0 * cosT - dy0 * sinT;
          const ty = ra.y + dx0 * sinT + dy0 * cosT;
          const tTheta = (pm.theta + dtheta + 2 * Math.PI) % (2 * Math.PI);

          let bestJ = -1;
          let bestDist = distTol;
          for (let j = 0; j < nR; j++) {
            if (usedRef.has(j)) continue;
            const rm = rMin[j];
            const dist = Math.hypot(tx - rm.x, ty - rm.y);
            if (dist > bestDist) continue;
            const aDiff =
              rm.type === 'bifurcation' || pm.type === 'bifurcation'
                ? axialAngleDiffRad(tTheta, rm.theta)
                : angleDiffRad(tTheta, rm.theta);
            if (aDiff <= angleTol) {
              bestDist = dist;
              bestJ = j;
            }
          }
          if (bestJ !== -1) {
            usedRef.add(bestJ);
            matchedCount++;
            const rmMatched = rMin[bestJ];
            const typeBonus = pm.type === rmMatched.type ? 1.0 : 0.72;
            const spatialConf = 1 - bestDist / (distTol * 1.4);
            const starBonus = 0.85 + 0.25 * localNeighborConsistency(pm, rmMatched);
            matchedWeighted += typeBonus * spatialConf * starBonus;
          }
        }

        if (matchedWeighted > bestMatchedWeighted) {
          bestMatchedWeighted = matchedWeighted;
          bestMatchedCount = matchedCount;
          bestDTheta = dtheta;
        }
      }
    }
  }

  const denomFull = Math.sqrt(nP * nR);
  const denomMin = Math.min(nP, nR);
  const isPartialMatch = nP < nR * 0.75 || nR < nP * 0.75;
  const fullRatio = denomFull > 0 ? bestMatchedWeighted / denomFull : 0;
  const partialRatio = denomMin > 0 && bestMatchedCount >= 7 ? (bestMatchedWeighted / denomMin) * 0.92 : fullRatio;
  const minutiaeRatio = isPartialMatch ? Math.max(fullRatio, partialRatio) : fullRatio;

  const scaledMinutiae = Math.min(1, minutiaeRatio * 1.38);
  const rawScore = 0.82 * scaledMinutiae + 0.18 * orientationScore;
  const clampedScore = Number(Math.max(0, Math.min(1, rawScore)).toFixed(4));

  let deg = ((bestDTheta * 180) / Math.PI) % 360;
  if (deg > 180) deg -= 360;
  if (deg < -180) deg += 360;

  const result: FingerprintMatchResult = {
    score: clampedScore,
    matchedMinutiae: bestMatchedCount,
    probeMinutiae: nP,
    refMinutiae: nR,
    orientationScore: Number(orientationScore.toFixed(4)),
    estimatedRotationDeg: Number(deg.toFixed(1)),
    isPartialMatch,
  };
  const cls = classifyFingerprintDecision(result, 0.72, probe.qualityScore, probe.validPrint);
  result.decision = cls.decision;
  result.decisionReason = cls.reason;
  return result;
}
