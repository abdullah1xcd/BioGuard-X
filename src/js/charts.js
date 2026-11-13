// Pure HTML5 Canvas visualizers for ROC curves, FAR/FRR thresholds, trends, modality comparisons, and waveforms

function getThemeColors() {
  const dark = !document.documentElement.classList.contains('light');
  return {
    bg: dark ? '#131e36' : '#f1f5f9',
    grid: dark ? '#1c2942' : '#e2e8f0',
    axis: dark ? '#475569' : '#94a3b8',
    text: dark ? '#cbd5e1' : '#334155',
    muted: dark ? '#94a3b8' : '#64748b',
    accent: dark ? '#06b6d4' : '#0891b2',
    accentSecondary: dark ? '#8b5cf6' : '#7c3aed',
    accentFill: dark ? 'rgba(6, 182, 212, 0.16)' : 'rgba(8, 145, 178, 0.10)',
    success: dark ? '#14b8a6' : '#0d9488',
    danger: dark ? '#ef4444' : '#dc2626',
    warning: dark ? '#f59e0b' : '#d97706',
  };
}

export function prepareHiDpiCanvas(canvas, baseW = 480, baseH = 240) {
  const parentW = canvas.parentElement?.clientWidth || baseW;
  const logicalW = Math.max(260, Math.min(900, Math.floor(parentW) || baseW));
  const aspect = baseH / Math.max(1, baseW);
  const logicalH = Math.max(160, Math.round(logicalW * aspect));
  const dpr = Math.min(2, typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1);
  canvas.width = Math.round(logicalW * dpr);
  canvas.height = Math.round(logicalH * dpr);
  canvas.style.width = '100%';
  canvas.style.height = `${logicalH}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w: logicalW, h: logicalH };
}

export function observeResponsiveChart(canvas, drawFn) {
  if (!canvas || typeof drawFn !== 'function') return () => {};
  drawFn(canvas);
  if (typeof ResizeObserver === 'undefined' || !canvas.parentElement) return () => {};
  let timer = null;
  const obs = new ResizeObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (document.body.contains(canvas)) drawFn(canvas);
    }, 60);
  });
  obs.observe(canvas.parentElement);
  return () => {
    clearTimeout(timer);
    obs.disconnect();
  };
}

export function drawRocChart(canvas, rocPoints, currentThreshold, auc) {
  if (!canvas) return;
  const { ctx, w, h } = prepareHiDpiCanvas(canvas, 480, 260);
  const c = getThemeColors();
  const pad = { l: 44, r: 16, t: 20, b: 40 };
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, w, h);

  ctx.strokeStyle = c.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const x = pad.l + (pw * i) / 4;
    const y = pad.t + (ph * i) / 4;
    ctx.beginPath(); ctx.moveTo(x, pad.t); ctx.lineTo(x, pad.t + ph); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + pw, y); ctx.stroke();
  }

  ctx.save();
  ctx.setLineDash([4, 4]);
  ctx.strokeStyle = c.axis;
  ctx.beginPath();
  ctx.moveTo(pad.l, pad.t + ph);
  ctx.lineTo(pad.l + pw, pad.t);
  ctx.stroke();
  ctx.restore();

  const sorted = [...rocPoints].sort((a, b) => a.far - b.far);
  if (sorted.length > 1) {
    ctx.beginPath();
    ctx.moveTo(pad.l, pad.t + ph);
    for (const pt of sorted) {
      ctx.lineTo(pad.l + pt.far * pw, pad.t + (1 - pt.tpr) * ph);
    }
    ctx.lineTo(pad.l + pw, pad.t + ph);
    ctx.closePath();
    ctx.fillStyle = c.accentFill;
    ctx.fill();

    ctx.beginPath();
    sorted.forEach((pt, idx) => {
      const x = pad.l + pt.far * pw;
      const y = pad.t + (1 - pt.tpr) * ph;
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = c.accent;
    ctx.lineWidth = 2.4;
    ctx.stroke();
  }

  const op = rocPoints.reduce((best, p) =>
    Math.abs(p.thr - currentThreshold) < Math.abs(best.thr - currentThreshold) ? p : best
  , rocPoints[0]);
  if (op) {
    const ox = pad.l + op.far * pw;
    const oy = pad.t + (1 - op.tpr) * ph;
    ctx.beginPath();
    ctx.arc(ox, oy, 5, 0, Math.PI * 2);
    ctx.fillStyle = c.danger;
    ctx.fill();
  }

  ctx.fillStyle = c.muted;
  ctx.font = '11px "JetBrains Mono", monospace';
  ctx.textAlign = 'center';
  ctx.fillText('False Acceptance Rate (FAR)', pad.l + pw / 2, h - 10);
  ctx.save();
  ctx.translate(14, pad.t + ph / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText('True Positive Rate (1 - FRR)', 0, 0);
  ctx.restore();

  ctx.fillStyle = c.text;
  ctx.textAlign = 'right';
  ctx.fillText(`AUC = ${auc.toFixed(3)}`, w - pad.r - 4, pad.t + 16);
}

export function drawFarFrrChart(canvas, rocPoints, currentThreshold, eerThreshold) {
  if (!canvas) return;
  const { ctx, w, h } = prepareHiDpiCanvas(canvas, 480, 260);
  const c = getThemeColors();
  const pad = { l: 44, r: 16, t: 20, b: 40 };
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, w, h);

  ctx.strokeStyle = c.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (ph * i) / 4;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + pw, y); ctx.stroke();
  }

  ctx.beginPath();
  rocPoints.forEach((pt, i) => {
    const x = pad.l + pt.thr * pw;
    const y = pad.t + (1 - pt.far) * ph;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = c.danger;
  ctx.lineWidth = 2.2;
  ctx.stroke();

  ctx.beginPath();
  rocPoints.forEach((pt, i) => {
    const x = pad.l + pt.thr * pw;
    const y = pad.t + (1 - pt.frr) * ph;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = c.accent;
  ctx.lineWidth = 2.2;
  ctx.stroke();

  const tx = pad.l + currentThreshold * pw;
  ctx.save();
  ctx.setLineDash([4, 3]);
  ctx.strokeStyle = c.warning;
  ctx.lineWidth = 1.6;
  ctx.beginPath(); ctx.moveTo(tx, pad.t); ctx.lineTo(tx, pad.t + ph); ctx.stroke();
  ctx.restore();

  ctx.fillStyle = c.muted;
  ctx.font = '11px "JetBrains Mono", monospace';
  ctx.textAlign = 'center';
  ctx.fillText(`Decision Threshold (EER @ ${eerThreshold.toFixed(2)})`, pad.l + pw / 2, h - 10);

  ctx.textAlign = 'left';
  ctx.fillStyle = c.danger;
  ctx.fillText('FAR', pad.l + 8, pad.t + 16);
  ctx.fillStyle = c.accent;
  ctx.fillText('FRR', pad.l + 44, pad.t + 16);
  ctx.fillStyle = c.warning;
  ctx.fillText(`Thr ${currentThreshold.toFixed(2)}`, Math.min(w - 70, Math.max(pad.l + 80, tx + 6)), pad.t + 16);
}

export function drawVerificationTrendChart(canvas, records) {
  if (!canvas) return;
  const { ctx, w, h } = prepareHiDpiCanvas(canvas, 480, 220);
  const c = getThemeColors();
  const pad = { l: 36, r: 14, t: 28, b: 34 };
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, w, h);

  const buckets = new Map();
  for (const r of records) {
    const ms = typeof r.createdAt?.toMillis === 'function'
      ? r.createdAt.toMillis()
      : typeof r.createdAt === 'string'
      ? Date.parse(r.createdAt)
      : Date.now();
    if (!ms || Number.isNaN(ms)) continue;
    const d = new Date(ms);
    const key = `${d.getMonth() + 1}/${d.getDate()}`;
    if (!buckets.has(key)) buckets.set(key, { key, ts: ms, match: 0, fail: 0 });
    const b = buckets.get(key);
    if (r.outcome === 'match') b.match++;
    else b.fail++;
  }

  const days = [...buckets.values()].sort((a, b) => a.ts - b.ts).slice(-10);
  if (days.length === 0) {
    ctx.fillStyle = c.muted;
    ctx.font = '12px "DM Sans", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No verification history in selected range', w / 2, h / 2);
    return;
  }

  const maxY = Math.max(2, ...days.map((d) => d.match + d.fail));
  ctx.strokeStyle = c.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = pad.t + (ph * i) / 3;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + pw, y); ctx.stroke();
  }

  const colW = pw / days.length;
  const barW = Math.min(26, Math.max(8, colW * 0.45));
  days.forEach((d, idx) => {
    const cx = pad.l + idx * colW + colW / 2;
    const matchH = (d.match / maxY) * ph;
    const failH = (d.fail / maxY) * ph;

    ctx.fillStyle = c.success;
    ctx.fillRect(cx - barW / 2, pad.t + ph - matchH - failH, barW, matchH);
    ctx.fillStyle = c.danger;
    ctx.fillRect(cx - barW / 2, pad.t + ph - failH, barW, failH);

    ctx.fillStyle = c.muted;
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(d.key, cx, h - 12);
  });

  ctx.textAlign = 'left';
  ctx.fillStyle = c.success;
  ctx.font = '11px "JetBrains Mono", monospace';
  ctx.fillText('Match', pad.l + 4, 16);
  ctx.fillStyle = c.danger;
  ctx.fillText('Reject/Other', pad.l + 52, 16);
}

export function drawModalityComparisonChart(canvas, perModality) {
  if (!canvas || !perModality) return;
  const { ctx, w, h } = prepareHiDpiCanvas(canvas, 480, 220);
  const c = getThemeColors();
  const pad = { l: 38, r: 14, t: 28, b: 34 };
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, w, h);

  ctx.strokeStyle = c.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (ph * i) / 4;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + pw, y); ctx.stroke();
  }

  const mods = [
    { key: 'face', label: 'Face' },
    { key: 'voice', label: 'Voice' },
    { key: 'fingerprint', label: 'FP' },
    { key: 'multimodal', label: 'Fused' },
  ];

  const colW = pw / mods.length;
  const barW = Math.min(24, colW * 0.28);

  mods.forEach((m, idx) => {
    const item = perModality[m.key];
    const cx = pad.l + idx * colW + colW / 2;
    const sim = typeof item?.meanSimilarity === 'number' ? item.meanSimilarity : 0;
    const acc = item?.metrics && !item.metrics.insufficientData ? item.metrics.accuracy : 0;

    if (sim > 0) {
      const sh = sim * ph;
      ctx.fillStyle = c.accent;
      ctx.fillRect(cx - barW - 2, pad.t + ph - sh, barW, sh);
    }
    if (acc > 0) {
      const ah = acc * ph;
      ctx.fillStyle = c.accentSecondary;
      ctx.fillRect(cx + 2, pad.t + ph - ah, barW, ah);
    }

    ctx.fillStyle = c.muted;
    ctx.font = '11px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(m.label, cx, h - 12);
  });

  ctx.textAlign = 'left';
  ctx.font = '11px "JetBrains Mono", monospace';
  ctx.fillStyle = c.accent;
  ctx.fillText('Mean Sim', pad.l + 4, 16);
  ctx.fillStyle = c.accentSecondary;
  ctx.fillText('Labeled Acc', pad.l + 76, 16);
}

export function drawWaveform(canvas, samples) {
  if (!canvas || !samples) return;
  const { ctx, w, h } = prepareHiDpiCanvas(canvas, 380, 86);
  const c = getThemeColors();

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, w, h);

  ctx.strokeStyle = c.grid;
  ctx.beginPath();
  ctx.moveTo(0, h / 2);
  ctx.lineTo(w, h / 2);
  ctx.stroke();

  const step = Math.max(1, Math.floor(samples.length / w));
  ctx.strokeStyle = c.accent;
  ctx.lineWidth = 1.4;
  ctx.beginPath();
  for (let x = 0; x < w; x++) {
    const start = x * step;
    let min = 1;
    let max = -1;
    for (let j = 0; j < step && start + j < samples.length; j++) {
      const s = samples[start + j];
      if (s < min) min = s;
      if (s > max) max = s;
    }
    const y1 = ((1 - max) / 2) * h;
    const y2 = ((1 - min) / 2) * h;
    ctx.moveTo(x, y1);
    ctx.lineTo(x, y2);
  }
  ctx.stroke();
}
