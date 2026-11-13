// Pure TypeScript Fingerprint Ridge Enhancement, Thinning, Minutiae Extraction & Matching Engine
// Implements:
// - 128x128 foreground variance segmentation & normalization
// - Gradient-tensor local ridge orientation & coherence estimation
// - Directional Gabor ridge enhancement
// - Zhang-Suen morphological skeletonization (1-px ridges)
// - Rutovitz Crossing Number minutiae extraction (endings & bifurcations) + spur pruning
// - Rotation & translation invariant RANSAC-style minutiae alignment + partial print support
// Feature version: v2.0-multimodal

export interface Minutia {
  x: number; // Normalized [0, 1]
  y: number; // Normalized [0, 1]
  theta: number; // Radians [0, 2*PI)
  type: 'ending' | 'bifurcation';
  quality: number; // [0, 1]
}

export interface FingerprintTemplate {
  version: string;
  descriptor128: number[]; // 4x4 grid x 8 orientation bins (L2-normalized)
  minutiae: Minutia[];
  ridgeDensity: number; // percentage 0..100
  meanCoherence: number; // 0..1
  foregroundRatio: number; // 0..1
  qualityScore: number; // 0..100
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
          sum += grayInput[(by * block + dy) * N + (bx * block + dx)];
        }
      }
      const mean = sum / (block * block);
      blockMean[by * gridN + bx] = mean;
      let vSum = 0;
      for (let dy = 0; dy < block; dy++) {
        for (let dx = 0; dx < block; dx++) {
          const d = grayInput[(by * block + dy) * N + (bx * block + dx)] - mean;
          vSum += d * d;
        }
      }
      blockVar[by * gridN + bx] = Math.sqrt(vSum / (block * block));
    }
  }

  // Foreground mask if block std dev > 8.5
  const fgBlock = new Uint8Array(gridN * gridN);
  for (let i = 0; i < fgBlock.length; i++) {
    fgBlock[i] = blockVar[i] > 8.5 ? 1 : 0;
  }
  // Fill single isolated holes
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

  // 2. Local contrast normalization inside foreground
  const norm = new Float32Array(N * N);
  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      const by = Math.floor(y / block);
      const bx = Math.floor(x / block);
      const m = blockMean[by * gridN + bx];
      const s = Math.max(12, blockVar[by * gridN + bx]);
      const z = (grayInput[y * N + x] - m) / s;
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
      // Ridge direction is perpendicular to gradient vector
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

      // Pool into 4x4 spatial x 8 orientation bins
      const bin = Math.min(7, Math.floor((ridgeAngle / Math.PI) * 8));
      const cy = Math.floor(y / 32);
      const cx = Math.floor(x / 32);
      orientHist[(cy * 4 + cx) * 8 + bin] += coh;
    }
  }
  const meanCoherence = cohCount > 0 ? cohSum / cohCount : 0;

  // 4. Directional Gabor ridge enhancement (ridges are dark: norm < 0, valleys > 0)
  // Invert norm so ridges are positive peaks, then apply aligned even Gabor kernel
  const enhanced = new Float32Array(N * N);
  const ridgeFreq = 1 / 7.5; // ~7.5 px ridge period on 128x128
  const sigma = 2.6;
  for (let y = 5; y < N - 5; y++) {
    for (let x = 5; x < N - 5; x++) {
      if (!fgMask[y * N + x]) continue;
      const theta = orient[y * N + x];
      const cosT = Math.cos(theta);
      const sinT = Math.sin(theta);
      let acc = 0;
      let wSum = 0;
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const xr = dx * cosT + dy * sinT;
          const yr = -dx * sinT + dy * cosT;
          const g = Math.exp(-(xr * xr + yr * yr) / (2 * sigma * sigma)) * Math.cos(2 * Math.PI * ridgeFreq * yr);
          // dark ridge -> -norm
          acc += -norm[(y + dy) * N + (x + dx)] * g;
          wSum += Math.abs(g);
        }
      }
      enhanced[y * N + x] = wSum > 0 ? acc / wSum : 0;
    }
  }

  // 5. Binarize enhanced ridges inside foreground mask
  const bin = new Uint8Array(N * N);
  let ridgePixels = 0;
  let fgPixels = 0;
  for (let y = 5; y < N - 5; y++) {
    for (let x = 5; x < N - 5; x++) {
      const idx = y * N + x;
      if (!fgMask[idx]) continue;
      fgPixels++;
      if (enhanced[idx] > 0.04) {
        bin[idx] = 1;
        ridgePixels++;
      }
    }
  }
  const ridgeDensity = fgPixels > 0 ? (ridgePixels / fgPixels) * 100 : 0;

  // 6. Zhang-Suen Thinning -> 1-px skeleton
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

  // 7. Rutovitz Crossing Number minutiae extraction inside eroded foreground mask
  const rawMinutiae: Array<{ px: number; py: number; theta: number; type: 'ending' | 'bifurcation'; quality: number }> = [];
  const margin = 8;
  for (let y = margin; y < N - margin; y++) {
    for (let x = margin; x < N - margin; x++) {
      if (skel[y * N + x] !== 1) continue;
      // Ensure 6px border inside foreground mask (ignore boundary edges)
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
          // Disambiguate continuous ridge tangent [0, PI) into full [0, 2*PI) using connected neighbor vector
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

  // 8. Prune spurious close pairs (< 6 px apart)
  const pruned: typeof rawMinutiae = [];
  rawMinutiae.sort((a, b) => b.quality - a.quality);
  for (const m of rawMinutiae) {
    const tooClose = pruned.some((k) => Math.hypot(k.px - m.px, k.py - m.py) < 6.0);
    if (!tooClose) pruned.push(m);
    if (pruned.length >= 64) break;
  }

  const minutiae: Minutia[] = pruned.map((m) => ({
    x: Number((m.px / N).toFixed(4)),
    y: Number((m.py / N).toFixed(4)),
    theta: Number(m.theta.toFixed(4)),
    type: m.type,
    quality: m.quality,
  }));

  const validPrint =
    foregroundRatio >= 0.14 &&
    meanCoherence >= 0.28 &&
    ridgeDensity >= 14 &&
    ridgeDensity <= 82 &&
    minutiae.length >= 4;

  const qualityScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(
        (Math.min(1, meanCoherence / 0.72) * 45) +
          (Math.min(1, minutiae.length / 24) * 35) +
          (Math.min(1, foregroundRatio / 0.55) * 20)
      )
    )
  );

  return {
    version: 'v2.0-multimodal',
    descriptor128: l2Norm(orientHist),
    minutiae,
    ridgeDensity: Number(ridgeDensity.toFixed(1)),
    meanCoherence: Number(meanCoherence.toFixed(3)),
    foregroundRatio: Number(foregroundRatio.toFixed(3)),
    qualityScore,
    validPrint,
  };
}

// Rotation & Translation Invariant Minutiae Matcher (RANSAC rigid transform alignment)
export function matchFingerprintTemplates(
  probe: FingerprintTemplate,
  ref: FingerprintTemplate
): FingerprintMatchResult {
  const pMin = probe.minutiae || [];
  const rMin = ref.minutiae || [];
  const nP = pMin.length;
  const nR = rMin.length;

  // Fallback ridge orientation similarity (calibrated dot product)
  let orientDot = 0;
  if (probe.descriptor128?.length === 128 && ref.descriptor128?.length === 128) {
    for (let i = 0; i < 128; i++) orientDot += probe.descriptor128[i] * ref.descriptor128[i];
  }
  const orientationScore = Math.max(0, Math.min(1, orientDot));

  if (nP < 4 || nR < 4) {
    return {
      score: Number((orientationScore * 0.65).toFixed(4)),
      matchedMinutiae: 0,
      probeMinutiae: nP,
      refMinutiae: nR,
      orientationScore: Number(orientationScore.toFixed(4)),
      estimatedRotationDeg: 0,
      isPartialMatch: false,
    };
  }

  let bestMatchedWeighted = 0;
  let bestMatchedCount = 0;
  let bestDTheta = 0;

  // Restrict anchor search to top-28 highest-quality minutiae for O(28^2 * 40) speed (< 2 ms)
  const pAnchors = pMin.slice(0, 28);
  const rAnchors = rMin.slice(0, 28);
  const distTol = 0.088; // ~11 px on 128x128
  const angleTol = (28 * Math.PI) / 180;

  for (const pa of pAnchors) {
    for (const ra of rAnchors) {
      if (pa.type !== ra.type) continue;
      const baseDTheta = ra.theta - pa.theta;
      // Check both direct rotation and +PI (for axial orientation symmetry on bifurcations)
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
            const aDiff = rm.type === 'bifurcation' || pm.type === 'bifurcation'
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
            const typeBonus = pm.type === rMin[bestJ].type ? 1.0 : 0.72;
            const spatialConf = 1 - bestDist / (distTol * 1.4);
            matchedWeighted += typeBonus * spatialConf;
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

  // Normalized Bozorth/NIST-style minutiae match ratio with partial print support
  const denomFull = Math.sqrt(nP * nR);
  const denomMin = Math.min(nP, nR);
  const isPartialMatch = nP < nR * 0.75 || nR < nP * 0.75;
  const fullRatio = denomFull > 0 ? bestMatchedWeighted / denomFull : 0;
  const partialRatio = denomMin > 0 && bestMatchedCount >= 7 ? (bestMatchedWeighted / denomMin) * 0.92 : fullRatio;
  const minutiaeRatio = isPartialMatch ? Math.max(fullRatio, partialRatio) : fullRatio;

  // Blend minutiae ratio (primary 82%) with orientation descriptor consistency (18%), scaled cleanly so >= 10 aligned minutiae scores >= 0.72
  const scaledMinutiae = Math.min(1, minutiaeRatio * 1.38);
  const rawScore = 0.82 * scaledMinutiae + 0.18 * orientationScore;
  const clampedScore = Number(Math.max(0, Math.min(1, rawScore)).toFixed(4));

  let deg = ((bestDTheta * 180) / Math.PI) % 360;
  if (deg > 180) deg -= 360;
  if (deg < -180) deg += 360;

  return {
    score: clampedScore,
    matchedMinutiae: bestMatchedCount,
    probeMinutiae: nP,
    refMinutiae: nR,
    orientationScore: Number(orientationScore.toFixed(4)),
    estimatedRotationDeg: Number(deg.toFixed(1)),
    isPartialMatch,
  };
}
