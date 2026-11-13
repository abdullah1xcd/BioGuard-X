import {
  extractFaceFeatures,
  extractVoiceFeaturesFromPCM,
  extractFingerprintFeatures,
  inspectLiveFaceGuidance,
  ensureFaceEngineReady,
  computeFrameMotion,
  decodeAudioFileToPCM,
} from './biometrics.js';
import { compareIdentities, identifyBiometricProbe } from './api.js';
import { appendAuditLog } from './firebase.js';
import { FUSION_POLICIES } from './config.js';
import { escapeHtml, fmtPct, showToast, loadImageFile, recordMicrophonePCM, openCameraStream, createLiveVideoElement } from './ui.js';

function snapVideoFrameCanvas(videoEl, width = 320, height = 240) {
  const c = document.createElement('canvas');
  c.width = width;
  c.height = height;
  c.getContext('2d').drawImage(videoEl, 0, 0, width, height);
  return c;
}

export function renderCompareIdentities(container, { appState, navigate }) {
  if (!appState.permissions.includes('perform_verification')) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Your role (${escapeHtml(appState.profile?.role)}) does not have permission for 1:1 comparison or 1:N identification search.</div></div></div>`;
    return;
  }

  const identities = appState.identities.filter((i) => i.status === 'active');
  const defaultPolicy = appState.settings?.fusionPolicy || 'hierarchical_adaptive';
  const preselected = appState.preselectedIdentityRef || identities[0]?.identityRef || '';
  appState.preselectedIdentityRef = '';

  let activeMode = 'one_to_one'; // 'one_to_one' | 'one_to_n'
  let searchSource = 'enrolled'; // 'enrolled' | 'probe'
  let faceVec = null;
  let faceQuality = null;
  let voiceVec = null;
  let voiceQuality = null;
  let fpTemplate = null;
  let fpQuality = null;
  let activeStream = null;
  let guidanceTimer = null;

  const stopCamera = () => {
    if (guidanceTimer) {
      clearInterval(guidanceTimer);
      guidanceTimer = null;
    }
    if (activeStream) {
      activeStream.getTracks().forEach((t) => t.stop());
      activeStream = null;
    }
  };

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Identity Search</h1>
        <p class="page-subtitle">Compare two enrolled identities (1:1) or search across the encrypted vault using a profile or captured probe (1:N).</p>
      </div>
      <div class="page-actions">
        <div class="segmented" id="cmp-mode-tabs">
          <button type="button" class="segmented-btn active" data-mode="one_to_one">1:1 Identity Compare</button>
          <button type="button" class="segmented-btn" data-mode="one_to_n">1:N Vault Search</button>
        </div>
      </div>
    </div>

    ${
      identities.length === 0
        ? `<section class="panel"><div class="empty-state"><div class="empty-title">No enrolled identities yet</div><div class="empty-desc">Enroll at least one identity to run 1:1 comparisons or 1:N biometric searches.</div><button type="button" class="btn btn-primary btn-sm" id="cmp-go-enroll">Open Enrollment</button></div></section>`
        : `
      <section class="panel stack-md" id="cmp-1to1-panel">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">1:1 Identity Comparison</h2>
            <p class="panel-subtitle">Evaluate all shared modalities between two enrolled biometric profiles.</p>
          </div>
        </div>

        <div class="form-grid">
          <div class="form-field">
            <label class="field-label" for="cmp-ref-a">Identity A</label>
            <select class="select" id="cmp-ref-a">
              ${identities.map((i) => `<option value="${escapeHtml(i.identityRef)}" ${i.identityRef === preselected ? 'selected' : ''}>${escapeHtml(i.displayName)} (${escapeHtml(i.identityRef)}) · [${escapeHtml((i.registeredModalities || []).join(', '))}]</option>`).join('')}
            </select>
          </div>
          <div class="form-field">
            <label class="field-label" for="cmp-ref-b">Identity B</label>
            <select class="select" id="cmp-ref-b">
              ${identities.map((i, idx) => `<option value="${escapeHtml(i.identityRef)}" ${idx === (identities.length > 1 ? 1 : 0) ? 'selected' : ''}>${escapeHtml(i.displayName)} (${escapeHtml(i.identityRef)}) · [${escapeHtml((i.registeredModalities || []).join(', '))}]</option>`).join('')}
            </select>
          </div>
        </div>

        <details class="advanced-details">
          <summary>Advanced Options (Fusion Policy)</summary>
          <div class="advanced-details-body">
            <div class="form-field">
              <label class="field-label" for="cmp-policy-1">Fusion Policy</label>
              <select class="select" id="cmp-policy-1">
                ${FUSION_POLICIES.map((fp) => `<option value="${fp.id}" ${fp.id === defaultPolicy ? 'selected' : ''}>${escapeHtml(fp.label)}</option>`).join('')}
              </select>
            </div>
          </div>
        </details>

        <div class="row-between">
          <span class="meta-line">Matched securely server-side without exposing biometric vectors.</span>
          <button type="button" class="btn btn-primary" id="cmp-run-1to1">Compare Identities (1:1)</button>
        </div>

        <div id="cmp-1to1-result"></div>
      </section>

      <section class="panel stack-md" id="cmp-1ton-panel" hidden>
        <div class="panel-header">
          <div>
            <h2 class="panel-title">1:N Vault Search</h2>
            <p class="panel-subtitle">Rank matching vault candidates from an enrolled profile or freshly captured probe.</p>
          </div>
          <div class="segmented" id="cmp-src-tabs">
            <button type="button" class="segmented-btn active" data-src="enrolled">From Enrolled Identity</button>
            <button type="button" class="segmented-btn" data-src="probe">From Live / Uploaded Probe</button>
          </div>
        </div>

        <div id="cmp-1ton-enrolled-box" class="form-grid">
          <div class="form-field">
            <label class="field-label" for="cmp-src-id">Source Identity Profile</label>
            <select class="select" id="cmp-src-id">
              ${identities.map((i) => `<option value="${escapeHtml(i.identityRef)}" ${i.identityRef === preselected ? 'selected' : ''}>${escapeHtml(i.displayName)} (${escapeHtml(i.identityRef)})</option>`).join('')}
            </select>
          </div>
          <div class="form-field" style="justify-content:flex-end;">
            <label class="checkbox-row">
              <input type="checkbox" id="cmp-exclude-self" checked />
              <span>Exclude source identity from ranked matches</span>
            </label>
          </div>
        </div>

        <div id="cmp-1ton-probe-box" class="grid-3" hidden>
          <div class="probe-card">
            <div class="row-between"><strong>Face Probe</strong><span id="idn-face-st" class="state-text state-neutral">Optional</span></div>
            <div id="idn-face-live" class="preview-frame" style="max-height:150px;" hidden></div>
            <div id="idn-face-q" class="meta-line">Live camera or photo upload</div>
            <div class="row-wrap">
              <button type="button" class="btn btn-secondary btn-sm" id="idn-face-cam">Live Camera</button>
              <button type="button" class="btn btn-primary btn-sm" id="idn-face-snap" hidden>Capture</button>
              <button type="button" class="btn btn-ghost btn-sm" id="idn-face-stop" hidden>Stop</button>
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload<input type="file" id="idn-face-file" accept="image/*" hidden /></label>
            </div>
          </div>

          <div class="probe-card">
            <div class="row-between"><strong>Voice Probe</strong><span id="idn-voice-st" class="state-text state-neutral">Optional</span></div>
            <div id="idn-voice-q" class="meta-line">2.4s Mic recording or audio file</div>
            <div class="row-wrap">
              <button type="button" class="btn btn-secondary btn-sm" id="idn-voice-mic">Mic (2.4s)</button>
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload<input type="file" id="idn-voice-file" accept="audio/*" hidden /></label>
            </div>
          </div>

          <div class="probe-card">
            <div class="row-between"><strong>Fingerprint Probe</strong><span id="idn-fp-st" class="state-text state-neutral">Optional</span></div>
            <div id="idn-fp-q" class="meta-line">Clear ridge image</div>
            <div class="row-wrap">
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Print<input type="file" id="idn-fp-file" accept="image/*" hidden /></label>
            </div>
          </div>
        </div>

        <details class="advanced-details">
          <summary>Advanced Options (Fusion Policy &amp; Result Limit)</summary>
          <div class="advanced-details-body">
            <div class="form-grid">
              <div class="form-field">
                <label class="field-label" for="cmp-policy-n">Fusion Policy</label>
                <select class="select" id="cmp-policy-n">
                  ${FUSION_POLICIES.map((fp) => `<option value="${fp.id}" ${fp.id === defaultPolicy ? 'selected' : ''}>${escapeHtml(fp.label)}</option>`).join('')}
                </select>
              </div>
              <div class="form-field">
                <label class="field-label" for="cmp-topk">Top-K Candidates</label>
                <select class="select mono" id="cmp-topk">
                  <option value="5" selected>Top 5</option>
                  <option value="10">Top 10</option>
                  <option value="20">Top 20</option>
                </select>
              </div>
            </div>
          </div>
        </details>

        <div class="row-between">
          <span class="meta-line">Evaluated server-side across your account's encrypted vault entries.</span>
          <button type="button" class="btn btn-primary" id="cmp-run-1ton">Search Vault (1:N)</button>
        </div>

        <div id="cmp-1ton-result"></div>
      </section>
    `
    }
  `;

  container.querySelector('#cmp-go-enroll')?.addEventListener('click', () => navigate('enrollment'));
  if (identities.length === 0) return stopCamera;

  const p1 = container.querySelector('#cmp-1to1-panel');
  const pn = container.querySelector('#cmp-1ton-panel');
  const enrolledBox = container.querySelector('#cmp-1ton-enrolled-box');
  const probeBox = container.querySelector('#cmp-1ton-probe-box');

  container.querySelectorAll('#cmp-mode-tabs .segmented-btn').forEach((b) => {
    b.addEventListener('click', () => {
      container.querySelectorAll('#cmp-mode-tabs .segmented-btn').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      activeMode = b.dataset.mode;
      p1.hidden = activeMode !== 'one_to_one';
      pn.hidden = activeMode !== 'one_to_n';
      if (activeMode !== 'one_to_n') stopCamera();
    });
  });

  container.querySelectorAll('#cmp-src-tabs .segmented-btn').forEach((b) => {
    b.addEventListener('click', () => {
      container.querySelectorAll('#cmp-src-tabs .segmented-btn').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      searchSource = b.dataset.src;
      enrolledBox.hidden = searchSource !== 'enrolled';
      probeBox.hidden = searchSource !== 'probe';
      if (searchSource !== 'probe') stopCamera();
    });
  });

  const getThresholds = () => {
    const s = appState.settings || {};
    return {
      face: s.faceThreshold ?? 0.72,
      voice: s.voiceThreshold ?? 0.70,
      fingerprint: s.fingerprintThreshold ?? 0.72,
      threeModal: s.threeModalThreshold ?? 0.74,
    };
  };

  // 1:1 Compare Handler
  container.querySelector('#cmp-run-1to1').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const refA = container.querySelector('#cmp-ref-a').value;
    const refB = container.querySelector('#cmp-ref-b').value;
    const fusionPolicy = container.querySelector('#cmp-policy-1').value;
    const outEl = container.querySelector('#cmp-1to1-result');

    btn.disabled = true;
    btn.textContent = 'Comparing...';
    try {
      const res = await compareIdentities({
        identityRefA: refA,
        identityRefB: refB,
        thresholds: getThresholds(),
        fusionPolicy,
      });

      await appendAuditLog({
        action: 'identity_1to1_compared',
        resourceType: 'identity',
        resourceId: `${refA}__${refB}`,
        result: `${res.outcome} sim=${fmtPct(res.fusedScore)} conf=${fmtPct(res.confidence)} shared=[${res.sharedModalities.join(',')}]`,
        requestId: res.requestId,
      }).catch(() => null);

      const outCls = res.outcome === 'match' ? 'state-success' : 'state-danger';
      const confCls = res.confidenceBand === 'high' ? 'state-success' : res.confidenceBand === 'moderate' ? 'state-warning' : 'state-danger';
      const rows = Object.entries(res.modalityEvaluations || {});

      outEl.innerHTML = `
        <div class="stack-md" style="padding-top:12px;border-top:1px solid var(--border-hairline);">
          <div class="row-between">
            <div class="stack-sm" style="gap:2px;">
              <span class="state-text ${outCls}">1:1 Result: ${escapeHtml(res.outcome.toUpperCase())}</span>
              <h3 class="panel-title"><span class="mono">${escapeHtml(res.identityRefA)}</span> vs <span class="mono">${escapeHtml(res.identityRefB)}</span></h3>
            </div>
            <div class="row-wrap">
              <div style="text-align:right;">
                <div class="meta-line" style="justify-content:flex-end;">Fused Similarity</div>
                <div class="mono" style="font-size:20px;font-weight:700;">${fmtPct(res.fusedScore)}</div>
              </div>
              <div style="text-align:right;padding-left:14px;border-left:1px solid var(--border-hairline);">
                <div class="meta-line" style="justify-content:flex-end;">Confidence</div>
                <div class="mono ${confCls}" style="font-size:18px;font-weight:700;">${fmtPct(res.confidence)} (${escapeHtml(res.confidenceBand)})</div>
              </div>
            </div>
          </div>

          ${
            res.sameIdentityRef
              ? `<div class="notice-strip warning"><div><strong>Same Identity Selected</strong><div>Identity A and Identity B point to the same enrolled reference (${escapeHtml(res.identityRefA)}). Select two distinct profiles for cross-identity testing.</div></div></div>`
              : ''
          }
          ${
            res.conflictDetected
              ? `<div class="notice-strip danger"><div><strong>Cross-Modality Conflict Detected</strong><div>${escapeHtml((res.conflictDetails || []).join(' '))}</div></div></div>`
              : ''
          }
          ${
            res.legacyCompatibility || (res.incompatibleModalities || []).length
              ? `<div class="notice-strip warning"><div><strong>Template Version Notice</strong><div>A: <span class="mono">${escapeHtml(res.featureVersionA)}</span> · B: <span class="mono">${escapeHtml(res.featureVersionB)}</span>${res.incompatibleModalities?.length ? ` · Skipped incompatible: ${escapeHtml(res.incompatibleModalities.join(', '))}` : ''}</div></div></div>`
              : ''
          }

          <div class="table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Shared Modality</th>
                  <th class="num-col">Similarity</th>
                  <th class="num-col">Threshold</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${rows
                  .map(([m, ev]) => {
                    const cls = ev.strongMismatch ? 'state-danger' : ev.passed ? 'state-success' : 'state-warning';
                    return `
                    <tr>
                      <td style="text-transform:capitalize;"><strong>${escapeHtml(m)}</strong></td>
                      <td class="num-col">${fmtPct(ev.score)}</td>
                      <td class="num-col">${fmtPct(ev.threshold)}</td>
                      <td><span class="state-text ${cls}">${ev.strongMismatch ? 'Strong Mismatch' : ev.passed ? 'Pass' : 'Below Thr'}</span></td>
                    </tr>`;
                  })
                  .join('')}
              </tbody>
            </table>
          </div>

          <details class="advanced-details">
            <summary>Advanced Details (Matcher Telemetry &amp; Request Info)</summary>
            <div class="advanced-details-body" style="font-size:12.5px;">
              <div class="meta-line">
                <span>Policy Threshold: <strong class="mono">${fmtPct(res.baseThreshold)}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Processing Time: <strong class="mono">${res.processingTimeMs} ms</strong></span>
                <span aria-hidden="true">·</span>
                <span>Request: <span class="mono">${escapeHtml(res.requestId)}</span></span>
              </div>
              ${rows
                .map(([m, ev]) => {
                  const det =
                    m === 'fingerprint' && typeof ev.details?.matchedMinutiae === 'number'
                      ? `${ev.details.matchedMinutiae}/${ev.details.probeMinutiae} minutiae · rotation ${ev.details.estimatedRotationDeg}°`
                      : typeof ev.rawCosine === 'number'
                      ? `rawCos=${ev.rawCosine} (${ev.details?.dim || ''}-D)`
                      : 'Matched';
                  return `<div class="row-between"><span style="text-transform:capitalize;">${escapeHtml(m)}</span><span class="mono">${escapeHtml(det)}</span></div>`;
                })
                .join('')}
            </div>
          </details>
        </div>
      `;
    } catch (err) {
      outEl.innerHTML = `<div class="notice-strip danger"><div><strong>Comparison Unavailable</strong><div>${escapeHtml(err.message)}</div></div></div>`;
      showToast(err.message, 'danger');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Compare Identities (1:1)';
    }
  });

  // 1:N Probe Capture Wiring
  const fSt = container.querySelector('#idn-face-st');
  const fQ = container.querySelector('#idn-face-q');
  const fLive = container.querySelector('#idn-face-live');
  const fSnap = container.querySelector('#idn-face-snap');
  const fStop = container.querySelector('#idn-face-stop');
  const vSt = container.querySelector('#idn-voice-st');
  const vQ = container.querySelector('#idn-voice-q');
  const fpSt = container.querySelector('#idn-fp-st');
  const fpQ = container.querySelector('#idn-fp-q');

  const haltIdnCam = () => {
    stopCamera();
    fSnap.hidden = true;
    fStop.hidden = true;
    fLive.hidden = true;
  };

  container.querySelector('#idn-face-cam').addEventListener('click', async () => {
    try {
      haltIdnCam();
      fSt.className = 'state-text state-warning';
      fSt.textContent = 'Starting Camera...';
      await ensureFaceEngineReady();
      activeStream = await openCameraStream();
      const wrap = document.createElement('div');
      wrap.className = 'face-guide-wrap';
      const v = await createLiveVideoElement(activeStream);
      const oval = document.createElement('div');
      oval.className = 'face-guide-oval';
      const msgBadge = document.createElement('div');
      msgBadge.className = 'face-guide-status';
      msgBadge.textContent = 'Align face in oval...';
      wrap.appendChild(v); wrap.appendChild(oval); wrap.appendChild(msgBadge);
      fLive.innerHTML = ''; fLive.appendChild(wrap);
      fLive.hidden = false; fSnap.hidden = false; fStop.hidden = false;
      fSt.textContent = 'Preview';

      guidanceTimer = setInterval(async () => {
        if (!activeStream) return;
        try {
          const g = await inspectLiveFaceGuidance(v);
          msgBadge.textContent = g.message;
          oval.classList.toggle('ready', Boolean(g.ready));
        } catch {
          // Ignore single frame errors
        }
      }, 450);

      fSnap.onclick = async () => {
        fSnap.disabled = true;
        try {
          const f1 = snapVideoFrameCanvas(v);
          await new Promise((r) => setTimeout(r, 250));
          const f2 = snapVideoFrameCanvas(v);
          const motion = computeFrameMotion(f1, f2);
          haltIdnCam();
          const res = await extractFaceFeatures(f2, { isLiveCapture: true, frameMotionScore: motion, captureSource: 'webcam' });
          faceVec = res.vector;
          faceQuality = res.quality;
          fSt.className = 'state-text state-success';
          fSt.textContent = 'Ready ✓';
          fQ.textContent = `Quality: ${faceQuality.faceQualityScore}/100`;
        } catch (err) {
          fSt.className = 'state-text state-danger';
          fSt.textContent = 'Rejected';
          fQ.textContent = err.message;
          showToast(err.message, 'danger');
        } finally {
          fSnap.disabled = false;
          haltIdnCam();
        }
      };
    } catch (err) {
      haltIdnCam();
      showToast(`Camera error: ${err.message}`, 'warning');
    }
  });

  fStop.addEventListener('click', () => {
    haltIdnCam();
    fSt.className = 'state-text state-neutral';
    fSt.textContent = faceVec ? 'Ready ✓' : 'Optional';
  });

  container.querySelector('#idn-face-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      stopCamera();
      fSt.className = 'state-text state-warning'; fSt.textContent = 'Analyzing...';
      const res = await extractFaceFeatures(await loadImageFile(f), { captureSource: 'upload' });
      faceVec = res.vector; faceQuality = res.quality;
      fSt.className = 'state-text state-success'; fSt.textContent = 'Ready (1024-D)';
      fQ.textContent = `Q:${faceQuality.faceQualityScore}/100`;
    } catch (err) {
      faceVec = null; faceQuality = null;
      fSt.className = 'state-text state-danger'; fSt.textContent = 'Rejected';
      fQ.textContent = err.message; showToast(err.message, 'danger');
    }
  });

  container.querySelector('#idn-voice-mic').addEventListener('click', async (e) => {
    const b = e.currentTarget; b.disabled = true;
    try {
      const p = await recordMicrophonePCM(2400, ({ elapsedSec, totalSec }) => {
        b.textContent = `${elapsedSec.toFixed(1)}/${totalSec.toFixed(1)}s`;
      });
      const res = extractVoiceFeaturesFromPCM(p.samples, p.sampleRate, 'microphone');
      voiceVec = res.vector; voiceQuality = res.stats;
      vSt.className = 'state-text state-success'; vSt.textContent = 'Ready (96-D)';
      vQ.textContent = `${voiceQuality.durationSec}s · Q:${voiceQuality.voiceQualityScore}/100`;
    } catch (err) {
      voiceVec = null; voiceQuality = null;
      vSt.className = 'state-text state-danger'; vSt.textContent = 'Rejected';
      vQ.textContent = err.message; showToast(err.message, 'warning');
    } finally {
      b.disabled = false; b.textContent = 'Mic (2.4s)';
    }
  });

  container.querySelector('#idn-voice-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const p = await decodeAudioFileToPCM(f);
      const res = extractVoiceFeaturesFromPCM(p.samples, p.sampleRate, 'upload');
      voiceVec = res.vector; voiceQuality = res.stats;
      vSt.className = 'state-text state-success'; vSt.textContent = 'Ready (96-D)';
      vQ.textContent = `${voiceQuality.durationSec}s · Q:${voiceQuality.voiceQualityScore}/100`;
    } catch (err) {
      voiceVec = null; voiceQuality = null;
      vSt.className = 'state-text state-danger'; vSt.textContent = 'Rejected';
      vQ.textContent = err.message; showToast(err.message, 'danger');
    }
  });

  container.querySelector('#idn-fp-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const res = extractFingerprintFeatures(await loadImageFile(f), 'upload');
      fpTemplate = res.template; fpQuality = res.quality;
      fpSt.className = 'state-text state-success'; fpSt.textContent = 'Ready (Minutiae)';
      fpQ.textContent = `Minutiae:${fpQuality.minutiaeHeuristicCount} · Q:${fpQuality.qualityScore}/100`;
    } catch (err) {
      fpTemplate = null; fpQuality = null;
      fpSt.className = 'state-text state-danger'; fpSt.textContent = 'Rejected';
      fpQ.textContent = err.message; showToast(err.message, 'danger');
    }
  });

  // 1:N Search Handler
  container.querySelector('#cmp-run-1ton').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const outEl = container.querySelector('#cmp-1ton-result');
    const fusionPolicy = container.querySelector('#cmp-policy-n').value;
    const topK = Number(container.querySelector('#cmp-topk').value || 5);

    const payload = {
      fusionPolicy,
      thresholds: getThresholds(),
      topK,
    };

    if (searchSource === 'enrolled') {
      payload.sourceIdentityRef = container.querySelector('#cmp-src-id').value;
      payload.excludeSelf = container.querySelector('#cmp-exclude-self').checked;
    } else {
      const samples = {};
      const quality = {};
      if (faceVec) { samples.face = faceVec; if (faceQuality) quality.face = faceQuality; }
      if (voiceVec) { samples.voice = voiceVec; if (voiceQuality) quality.voice = voiceQuality; }
      if (fpTemplate) { samples.fingerprint = fpTemplate; if (fpQuality) quality.fingerprint = fpQuality; }
      if (!Object.keys(samples).length) {
        showToast('Capture or upload at least one biometric probe before running 1:N search.', 'warning');
        return;
      }
      payload.samples = samples;
      payload.quality = quality;
    }

    btn.disabled = true;
    btn.textContent = 'Searching Vault...';
    try {
      const res = await identifyBiometricProbe(payload);
      await appendAuditLog({
        action: 'identity_1ton_searched',
        resourceType: 'vault',
        resourceId: res.probeSource,
        result: `Evaluated ${res.totalCandidatesEvaluated} candidate(s); matchesAboveThreshold=${res.matchesAboveThreshold} (${res.processingTimeMs}ms)`,
        requestId: res.requestId,
      }).catch(() => null);

      outEl.innerHTML = `
        <div class="stack-md" style="padding-top:12px;border-top:1px solid var(--border-hairline);">
          <div class="meta-line">
            <span>Source: <strong class="mono">${escapeHtml(res.probeSource)}</strong></span>
            <span aria-hidden="true">·</span>
            <span>Evaluated: <strong>${res.compatibleCandidates}</strong> / ${res.totalCandidatesEvaluated} candidate(s)</span>
            <span aria-hidden="true">·</span>
            <span>Matches Above Threshold: <strong class="${res.matchesAboveThreshold > 0 ? 'state-success' : 'state-neutral'}">${res.matchesAboveThreshold}</strong></span>
            <span aria-hidden="true">·</span>
            <span>Search Latency: <strong class="mono">${res.processingTimeMs} ms</strong></span>
          </div>

          ${
            res.incompatibleCandidates > 0
              ? `<div class="notice-strip warning"><div><strong>${res.incompatibleCandidates} Candidate(s) Skipped Due to Legacy Feature Version</strong><div>Legacy v1.x enrollments differ in embedding dimensionality from v2.0 probes. Re-enroll legacy identities to include them in cross-version 1:N searches.</div></div></div>`
              : ''
          }

          ${
            res.rankedMatches.length === 0
              ? `<div class="empty-state"><div class="empty-title">No compatible candidate templates found</div><div class="empty-desc">Enroll more identities sharing the probed modality to populate 1:N search rankings.</div></div>`
              : `<div class="table-wrap">
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>Candidate Ref</th>
                        <th>Shared Modalities</th>
                        <th class="num-col">Similarity</th>
                        <th class="num-col">Confidence</th>
                        <th>Decision</th>
                        <th>Per-Modality</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${res.rankedMatches
                        .map((m) => {
                          const cls = m.outcome === 'match' ? 'state-success' : 'state-danger';
                          const modStr = Object.entries(m.modalityScores || {})
                            .map(([k, v]) => `${k}:${(v * 100).toFixed(0)}%`)
                            .join(' ');
                          return `
                          <tr>
                            <td class="mono"><strong>#${m.rank}</strong></td>
                            <td class="mono"><strong>${escapeHtml(m.identityRef)}</strong></td>
                            <td class="mono">${escapeHtml(m.sharedModalities.join(', '))}</td>
                            <td class="num-col">${fmtPct(m.fusedScore)}</td>
                            <td class="num-col">${fmtPct(m.confidence)} (${escapeHtml(m.confidenceBand)})</td>
                            <td><span class="state-text ${cls}">${escapeHtml(m.outcome)}${m.conflictDetected ? ' (conflict)' : ''}</span></td>
                            <td class="mono" style="font-size:12px;">${escapeHtml(modStr)}</td>
                            <td><button type="button" class="btn btn-ghost btn-sm" data-verify-cand="${escapeHtml(m.identityRef)}">Verify 1:1</button></td>
                          </tr>`;
                        })
                        .join('')}
                    </tbody>
                  </table>
                </div>`
          }
        </div>
      `;

      outEl.querySelectorAll('[data-verify-cand]').forEach((b) => {
        b.addEventListener('click', () => navigate('verification', { identityRef: b.dataset.verifyCand }));
      });
    } catch (err) {
      outEl.innerHTML = `<div class="notice-strip danger"><div><strong>1:N Search Error</strong><div>${escapeHtml(err.message)}</div></div></div>`;
      showToast(err.message, 'danger');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Search Vault (1:N)';
    }
  });

  return stopCamera;
}
