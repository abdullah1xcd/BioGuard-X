export function escapeHtml(str) {
  return String(str ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function fmtPct(val) {
  return `${(Number(val) * 100).toFixed(1)}%`;
}

export function showToast(message, tone = 'neutral') {
  const region = document.getElementById('toast-region');
  if (!region) return;
  const el = document.createElement('div');
  el.className = 'toast';
  const toneClass =
    tone === 'success'
      ? 'state-success'
      : tone === 'warning'
      ? 'state-warning'
      : tone === 'danger'
      ? 'state-danger'
      : 'state-neutral';
  el.innerHTML = `
    <div class="stack-sm" style="gap:2px;">
      <span class="state-text ${toneClass}">${tone === 'neutral' ? 'Notice' : tone.charAt(0).toUpperCase() + tone.slice(1)}</span>
      <span>${escapeHtml(message)}</span>
    </div>
    <button type="button" class="btn btn-ghost btn-sm" aria-label="Dismiss notification">Dismiss</button>
  `;
  el.querySelector('button').addEventListener('click', () => el.remove());
  region.appendChild(el);
  setTimeout(() => {
    if (el.isConnected) el.remove();
  }, 4500);
}

export function openModal({ title, bodyHtml, footerButtons = [] }) {
  const root = document.getElementById('modal-root');
  const titleEl = document.getElementById('modal-title');
  const bodyEl = document.getElementById('modal-body');
  const footerEl = document.getElementById('modal-footer');
  if (!root) return;

  titleEl.textContent = title;
  bodyEl.innerHTML = bodyHtml;
  footerEl.innerHTML = '';

  for (const btnCfg of footerButtons) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = `btn ${btnCfg.variant || 'btn-secondary'}`;
    b.textContent = btnCfg.label;
    b.addEventListener('click', () => {
      if (btnCfg.onClick) btnCfg.onClick({ close: closeModal, bodyEl });
      else closeModal();
    });
    footerEl.appendChild(b);
  }

  root.hidden = false;
}

export function closeModal() {
  const root = document.getElementById('modal-root');
  if (root) root.hidden = true;
}

export function downloadFile(filename, content, mimeType = 'text/csv;charset=utf-8;') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function loadImageFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Could not decode image file.'));
    };
    img.src = url;
  });
}

// Generate procedural deterministic grayscale fingerprint test image with ridge bifurcations/endings
export function renderSampleFingerprintCanvas(seedText, width = 180, height = 180) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#e2e8f0';
  ctx.fillRect(0, 0, width, height);

  let h = 2166136261;
  for (let i = 0; i < seedText.length; i++) {
    h ^= seedText.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const nextRand = () => {
    h ^= h << 13;
    h ^= h >>> 17;
    h ^= h << 5;
    return (h >>> 0) / 4294967295;
  };

  const cx = width / 2 + (nextRand() - 0.5) * 16;
  const cy = height / 2 + (nextRand() - 0.5) * 16;
  const phaseMod = 1.6 + nextRand() * 2.2;
  const skewX = 0.95 + nextRand() * 0.25;
  const skewY = 0.78 + nextRand() * 0.22;

  // Deterministic phase dislocations (yield real ridge endings & bifurcations)
  const singularities = [];
  for (let i = 0; i < 6; i++) {
    const ang = nextRand() * Math.PI * 2;
    const rad = 18 + nextRand() * 44;
    singularities.push({
      x: cx + Math.cos(ang) * rad,
      y: cy + Math.sin(ang) * rad,
      sign: i % 2 === 0 ? 1 : -1,
    });
  }

  const imgData = ctx.getImageData(0, 0, width, height);
  const data = imgData.data;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const dx = (x - cx) * skewX;
      const dy = (y - cy) * skewY;
      const r = Math.hypot(dx, dy);
      const ell = Math.hypot(dx / 74, dy / 86);
      const idx = (y * width + x) * 4;
      if (ell > 1) {
        data[idx] = 241;
        data[idx + 1] = 245;
        data[idx + 2] = 249;
        data[idx + 3] = 255;
        continue;
      }
      const theta = Math.atan2(dy, dx);
      let phaseShift = 0;
      for (const s of singularities) {
        const sDist = Math.hypot(x - s.x, y - s.y);
        if (sDist < 42) {
          phaseShift += s.sign * 0.55 * Math.atan2(y - s.y, x - s.x) * Math.exp(-sDist / 28);
        }
      }
      const ridge = Math.sin(r * 0.56 + Math.sin(theta * 2 + phaseMod) * 2.1 + phaseShift);
      const val = ridge > 0 ? 34 : 230;
      data[idx] = val;
      data[idx + 1] = val;
      data[idx + 2] = val;
      data[idx + 3] = 255;
    }
  }
  ctx.putImageData(imgData, 0, 0);
  return canvas;
}

// Illustrative QA avatar preview canvas (synthetic non-camera test marker)
export function renderSampleFaceCanvas(seedText, width = 240, height = 180) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  let h = 2166136261;
  for (let i = 0; i < seedText.length; i++) {
    h ^= seedText.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, width, height);

  const eyeSpread = 24 + (h % 10);
  const jawW = 46 + ((h >> 4) % 12);
  ctx.fillStyle = '#cbd5e1';
  ctx.beginPath();
  ctx.ellipse(width / 2, height / 2, jawW, 60, 0, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = '#334155';
  ctx.beginPath();
  ctx.arc(width / 2 - eyeSpread, height / 2 - 14, 7, 0, Math.PI * 2);
  ctx.arc(width / 2 + eyeSpread, height / 2 - 14, 7, 0, Math.PI * 2);
  ctx.fill();

  ctx.strokeStyle = '#475569';
  ctx.lineWidth = 3.5;
  ctx.beginPath();
  ctx.moveTo(width / 2, height / 2 - 10);
  ctx.lineTo(width / 2, height / 2 + 16);
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(width / 2, height / 2 + 26, 15, 0.15 * Math.PI, 0.85 * Math.PI);
  ctx.stroke();

  ctx.fillStyle = '#06b6d4';
  ctx.font = '600 10px "JetBrains Mono", monospace';
  ctx.fillText('SYNTHETIC QA PROBE', 10, height - 10);
  return canvas;
}

// Generate deterministic synthesized speech-like PCM buffer (2s @ 16kHz) with natural F0 vibrato & formant harmonics
export function synthesizeSampleVoicePCM(seedText, segments = 3, sampleRate = 16000) {
  const total = sampleRate * 2;
  const samples = new Float32Array(total);
  let h = 2166136261;
  for (let i = 0; i < seedText.length; i++) {
    h ^= seedText.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const f0 = 108 + (h % 115);
  const formant2Gain = 0.16 + ((h >> 4) % 15) * 0.015;
  const formant3Gain = 0.08 + ((h >> 8) % 12) * 0.01;
  const segLen = Math.floor(total / (segments * 2 + 1));

  for (let s = 0; s < segments; s++) {
    const start = (s * 2 + 1) * segLen;
    const end = Math.min(total, start + segLen);
    for (let i = start; i < end; i++) {
      const t = i / sampleRate;
      const fInst = f0 * (1 + 0.025 * Math.sin(2 * Math.PI * 4.8 * t));
      const env = Math.sin(((i - start) / (end - start)) * Math.PI);
      const breath = 0.012 * Math.sin(i * 12.9898);
      samples[i] =
        env *
        (0.36 * Math.sin(2 * Math.PI * fInst * t) +
          formant2Gain * Math.sin(2 * Math.PI * fInst * 2.04 * t) +
          formant3Gain * Math.sin(2 * Math.PI * fInst * 3.12 * t) +
          0.05 * Math.sin(2 * Math.PI * fInst * 4.4 * t) +
          breath);
    }
  }
  return { samples, sampleRate };
}

export function encodeWavBlobUrl(samples, sampleRate = 16000) {
  const buffer = new ArrayBuffer(44 + samples.length * 2);
  const view = new DataView(buffer);
  const writeStr = (off, s) => {
    for (let i = 0; i < s.length; i++) view.setUint8(off + i, s.charCodeAt(i));
  };
  writeStr(0, 'RIFF');
  view.setUint32(4, 36 + samples.length * 2, true);
  writeStr(8, 'WAVE');
  writeStr(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeStr(36, 'data');
  view.setUint32(40, samples.length * 2, true);
  let off = 44;
  for (let i = 0; i < samples.length; i++, off += 2) {
    const clamped = Math.max(-1, Math.min(1, samples[i]));
    view.setInt16(off, clamped < 0 ? clamped * 0x8000 : clamped * 0x7fff, true);
  }
  return URL.createObjectURL(new Blob([buffer], { type: 'audio/wav' }));
}

// Record audio from browser microphone with live elapsed/RMS progress & WAV playback URL
export async function recordMicrophonePCM(durationMs = 2400, onProgress) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Microphone API is unavailable in this browser context. Open over HTTPS or install as an app.');
  }
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) {
    throw new Error('Web Audio API is unavailable in this browser.');
  }
  const ctx = new AudioCtx();
  if (ctx.state === 'suspended') {
    await ctx.resume().catch(() => null);
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: false },
    });
  } catch {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (err) {
      await ctx.close().catch(() => null);
      throw err;
    }
  }

  const source = ctx.createMediaStreamSource(stream);
  const processor = ctx.createScriptProcessor(4096, 1, 1);
  const chunks = [];
  const startedAt = performance.now();

  processor.onaudioprocess = (e) => {
    const ch = new Float32Array(e.inputBuffer.getChannelData(0));
    chunks.push(ch);
    if (onProgress) {
      let sum = 0;
      for (let i = 0; i < ch.length; i++) sum += ch[i] * ch[i];
      const rms = Math.sqrt(sum / ch.length);
      const elapsedSec = Math.min(durationMs / 1000, (performance.now() - startedAt) / 1000);
      onProgress({ elapsedSec, totalSec: durationMs / 1000, rms });
    }
  };

  source.connect(processor);
  processor.connect(ctx.destination);

  await new Promise((resolve) => setTimeout(resolve, durationMs));

  processor.disconnect();
  source.disconnect();
  stream.getTracks().forEach((t) => t.stop());
  const sampleRate = ctx.sampleRate;
  await ctx.close();

  const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Float32Array(totalLen);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  const wavUrl = encodeWavBlobUrl(out, sampleRate);
  return { samples: out, sampleRate, wavUrl };
}

export async function openCameraStream() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Camera API is unavailable in this browser context. Use HTTPS or install the app.');
  }
  const attempts = [
    { video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false },
    { video: { facingMode: 'user' }, audio: false },
    { video: true, audio: false },
  ];
  let lastErr;
  for (const constraints of attempts) {
    try {
      return await navigator.mediaDevices.getUserMedia(constraints);
    } catch (err) {
      lastErr = err;
      if (err?.name === 'NotAllowedError' || err?.name === 'PermissionDeniedError') {
        throw new Error('Camera permission was denied. Allow camera access in your browser/device settings.', { cause: err });
      }
    }
  }
  throw lastErr || new Error('Unable to access device camera.');
}

export async function createLiveVideoElement(stream) {
  const v = document.createElement('video');
  v.autoplay = true;
  v.playsInline = true;
  v.muted = true;
  v.setAttribute('autoplay', '');
  v.setAttribute('playsinline', '');
  v.setAttribute('muted', '');
  v.srcObject = stream;
  await v.play().catch(() => null);
  return v;
}

