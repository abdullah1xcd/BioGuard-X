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

// Load an uploaded image File into an HTMLImageElement
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

// Generate a procedural deterministic grayscale fingerprint test image on a canvas
// so users without a physical fingerprint sensor file can still test image extraction & matching
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
  const cx = width / 2 + ((h % 19) - 9);
  const cy = height / 2 + (((h >> 5) % 19) - 9);
  const imgData = ctx.getImageData(0, 0, width, height);
  const data = imgData.data;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const dx = (x - cx) * 1.05;
      const dy = (y - cy) * 0.85;
      const r = Math.hypot(dx, dy);
      const ell = Math.hypot(dx / 72, dy / 86);
      const idx = (y * width + x) * 4;
      if (ell > 1) {
        data[idx] = 241;
        data[idx + 1] = 245;
        data[idx + 2] = 249;
        data[idx + 3] = 255;
        continue;
      }
      const theta = Math.atan2(dy, dx);
      const ridge = Math.sin(r * 0.55 + Math.sin(theta * 2 + (h % 7)) * 2.2);
      const val = ridge > 0 ? 38 : 228;
      data[idx] = val;
      data[idx + 1] = val;
      data[idx + 2] = val;
      data[idx + 3] = 255;
    }
  }
  ctx.putImageData(imgData, 0, 0);
  return canvas;
}

// Generate a procedural deterministic face-like grayscale pattern canvas for testing without webcam
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
  ctx.fillStyle = '#1e293b';
  ctx.fillRect(0, 0, width, height);

  const eyeSpread = 24 + (h % 10);
  const jawW = 48 + ((h >> 4) % 12);
  ctx.fillStyle = '#cbd5e1';
  ctx.beginPath();
  ctx.ellipse(width / 2, height / 2, jawW, 64, 0, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = '#334155';
  ctx.beginPath();
  ctx.arc(width / 2 - eyeSpread, height / 2 - 14, 7, 0, Math.PI * 2);
  ctx.arc(width / 2 + eyeSpread, height / 2 - 14, 7, 0, Math.PI * 2);
  ctx.fill();

  ctx.strokeStyle = '#475569';
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.moveTo(width / 2, height / 2 - 10);
  ctx.lineTo(width / 2, height / 2 + 16);
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(width / 2, height / 2 + 28, 16, 0.15 * Math.PI, 0.85 * Math.PI);
  ctx.stroke();
  return canvas;
}

// Generate deterministic synthesized audio PCM buffer (2 seconds @ 16kHz) for mic-free testing
export function synthesizeSampleVoicePCM(seedText, segments = 3, sampleRate = 16000) {
  const total = sampleRate * 2;
  const samples = new Float32Array(total);
  let h = 2166136261;
  for (let i = 0; i < seedText.length; i++) {
    h ^= seedText.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const f0 = 115 + (h % 95);
  const segLen = Math.floor(total / (segments * 2 + 1));

  for (let s = 0; s < segments; s++) {
    const start = (s * 2 + 1) * segLen;
    const end = Math.min(total, start + segLen);
    for (let i = start; i < end; i++) {
      const t = i / sampleRate;
      const env = Math.sin(((i - start) / (end - start)) * Math.PI);
      samples[i] =
        env *
        (0.35 * Math.sin(2 * Math.PI * f0 * t) +
          0.18 * Math.sin(2 * Math.PI * f0 * 2.02 * t) +
          0.09 * Math.sin(2 * Math.PI * f0 * 3.1 * t));
    }
  }
  return { samples, sampleRate };
}

// Record audio from browser microphone for N milliseconds
export async function recordMicrophonePCM(durationMs = 2400) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Microphone API is unavailable in this browser context.');
  }
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const ctx = new AudioCtx();
  const source = ctx.createMediaStreamSource(stream);
  const processor = ctx.createScriptProcessor(4096, 1, 1);
  const chunks = [];

  processor.onaudioprocess = (e) => {
    chunks.push(new Float32Array(e.inputBuffer.getChannelData(0)));
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
  return { samples: out, sampleRate };
}
