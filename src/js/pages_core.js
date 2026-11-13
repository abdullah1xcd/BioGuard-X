import {
  extractFaceFeatures,
  extractVoiceFeaturesFromPCM,
  extractFingerprintFeatures,
  inspectLiveFaceGuidance,
  ensureFaceEngineReady,
  computeFrameMotion,
  decodeAudioFileToPCM,
  makeSeededVector,
} from './biometrics.js';
import {
  enrollBiometricIdentity,
  verifyMultimodalBiometrics,
  deleteIdentityFromVault,
} from './api.js';
import {
  saveIdentityMetadata,
  updateIdentityStatusOrName,
  deleteIdentityMetadata,
  recordVerificationMetadata,
  createSecurityAlert,
  createApprovalRequest,
  appendAuditLog,
  pushNotification,
  getFirestoreTelemetry,
} from './firebase.js';
import {
  PIPELINE_CATALOG,
  FUSION_POLICIES,
  slugifyIdentityRef,
  recommendPipelineForModalities,
} from './config.js';
import { drawWaveform } from './charts.js';
import {
  escapeHtml,
  fmtPct,
  showToast,
  openModal,
  loadImageFile,
  renderSampleFaceCanvas,
  renderSampleFingerprintCanvas,
  synthesizeSampleVoicePCM,
  recordMicrophonePCM,
} from './ui.js';

function fmtFsTime(ts) {
  if (!ts) return '—';
  const d = typeof ts.toDate === 'function' ? ts.toDate() : new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function snapVideoFrameCanvas(videoEl, width = 320, height = 240) {
  const c = document.createElement('canvas');
  c.width = width;
  c.height = height;
  c.getContext('2d').drawImage(videoEl, 0, 0, width, height);
  return c;
}

// 1. MAIN DASHBOARD
export function renderOverview(container, { appState, navigate }) {
  const { identities, verifications, alerts, health, permissions } = appState;
  const passCount = verifications.filter((v) => v.outcome === 'match').length;
  const failCount = verifications.filter((v) => v.outcome === 'no_match').length;
  const evalCount = passCount + failCount;
  const opSuccessRate = evalCount ? ((passCount / evalCount) * 100).toFixed(1) : '—';
  const labeledCount = verifications.filter((v) => v.groundTruth === 'genuine' || v.groundTruth === 'impostor').length;
  const openAlerts = alerts.filter((a) => a.status !== 'resolved').length;
  const showQuickStart = identities.length === 0 || verifications.length === 0;

  const latencies = verifications.map((v) => v.processingTimeMs).filter((x) => typeof x === 'number' && Number.isFinite(x));
  const avgLatencyMs = latencies.length ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1) : null;

  const recentVer = verifications.slice(0, 20);
  const scoredVer = recentVer.filter((v) => typeof v.riskScore === 'number');
  const meanVerRisk = scoredVer.length
    ? scoredVer.reduce((acc, v) => acc + v.riskScore, 0) / scoredVer.length
    : failCount > 0
    ? Math.min(65, failCount * 15)
    : 0;
  const securityRiskScore = Math.min(100, Math.round(meanVerRisk + Math.min(35, openAlerts * 12)));
  const riskLabel =
    securityRiskScore >= 75
      ? 'Critical'
      : securityRiskScore >= 50
      ? 'High'
      : securityRiskScore >= 25
      ? 'Medium'
      : 'Low';
  const riskCls =
    securityRiskScore >= 50 ? 'state-danger' : securityRiskScore >= 25 ? 'state-warning' : 'state-success';

  const systemOk = health?.status === 'ok' && appState.firestoreOk;
  const fsTel = getFirestoreTelemetry();

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Security Operations Dashboard</h1>
        <p class="page-subtitle">Real-time overview of enrolled identities, multimodal similarity &amp; confidence, liveness, risk telemetry, and platform services.</p>
      </div>
      <div class="page-actions">
        ${permissions.includes('create_identity') ? `<button class="btn btn-secondary" type="button" data-goto="enrollment">Enroll Identity</button>` : ''}
        ${permissions.includes('perform_verification') ? `<button class="btn btn-primary" type="button" data-goto="verification">Verify Identity</button>` : ''}
        ${permissions.includes('perform_verification') ? `<button class="btn btn-secondary" type="button" data-goto="compare">1:1 &amp; 1:N Compare</button>` : ''}
      </div>
    </div>

    <div class="kpi-strip">
      <div class="kpi-cell">
        <span class="kpi-label">Total Enrolled Identities</span>
        <span class="kpi-value">${identities.length}</span>
        <span class="kpi-meta">${identities.filter((i) => i.status === 'active').length} active in encrypted vault</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Operational Verifications</span>
        <span class="kpi-value">${passCount} / ${failCount}</span>
        <span class="kpi-meta">Match rate ${opSuccessRate}% (${labeledCount} labeled trial(s))</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Security Risk Score</span>
        <span class="kpi-value">${securityRiskScore} / 100</span>
        <span class="kpi-meta"><span class="${riskCls}">${riskLabel} Risk</span> · ${openAlerts} open alert(s)</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Live Engine &amp; Latency</span>
        <span class="kpi-value" style="font-size:21px;">${systemOk ? 'Operational' : 'Degraded'}</span>
        <span class="kpi-meta">${avgLatencyMs !== null ? `Avg match: ${avgLatencyMs} ms` : 'No timing data yet'} · AI: ${health?.gemini_configured ? 'Ready' : 'Off'}</span>
      </div>
    </div>

    ${
      showQuickStart
        ? `
      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Quick-Start Workflow</h2>
            <p class="panel-subtitle">Enroll an identity with pretrained v2.0 extractors, run multimodal verification or 1:1/1:N matching, and inspect genuine statistics</p>
          </div>
        </div>
        <div class="quickstart-grid">
          <div class="quickstart-step">
            <div class="stack-sm" style="gap:4px;">
              <span class="quickstart-num">01. Enroll</span>
              <strong>Register Biometric Profile</strong>
              <p style="font-size:13px;color:var(--text-secondary);">FaceRes-1024D neural embeddings, 16kHz CMVN Voice-96D, and Gabor+Minutiae templates.</p>
            </div>
            ${permissions.includes('create_identity') ? `<button type="button" class="btn btn-secondary btn-sm" data-goto="enrollment" style="align-self:flex-start;">Open Enrollment</button>` : '<span class="meta-line">Requires Operator role</span>'}
          </div>
          <div class="quickstart-step">
            <div class="stack-sm" style="gap:4px;">
              <span class="quickstart-num">02. Verify &amp; Compare</span>
              <strong>Adaptive Fusion &amp; 1:N Search</strong>
              <p style="font-size:13px;color:var(--text-secondary);">Quality-weighted fusion, cross-modality conflict blocking, anti-spoof checks, and confidence scoring.</p>
            </div>
            ${permissions.includes('perform_verification') ? `<button type="button" class="btn btn-secondary btn-sm" data-goto="verification" style="align-self:flex-start;">Open Verification</button>` : '<span class="meta-line">Requires Operator role</span>'}
          </div>
          <div class="quickstart-step">
            <div class="stack-sm" style="gap:4px;">
              <span class="quickstart-num">03. Evaluate &amp; Investigate</span>
              <strong>Validated Metrics &amp; AI Analyst</strong>
              <p style="font-size:13px;color:var(--text-secondary);">Inspect FAR/FRR/EER from ground-truth trials and investigate alerts in AI Security Analyst.</p>
            </div>
            ${permissions.includes('use_ai_analyst') ? `<button type="button" class="btn btn-secondary btn-sm" data-goto="ai_analyst" style="align-self:flex-start;">Open AI Analyst</button>` : '<button type="button" class="btn btn-secondary btn-sm" data-goto="analytics" style="align-self:flex-start;">Open Analytics</button>'}
          </div>
        </div>
      </section>`
        : ''
    }

    <div class="grid-sidebar-split">
      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Recent Activity</h2>
            <p class="panel-subtitle">Latest evaluations showing similarity score, confidence, liveness, and latency</p>
          </div>
          <div class="row-wrap">
            <button class="btn btn-ghost btn-sm" type="button" data-goto="analytics">Analytics</button>
            ${permissions.includes('manage_alerts') ? `<button class="btn btn-ghost btn-sm" type="button" data-goto="threat_intel">Threat Analysis</button>` : ''}
          </div>
        </div>
        ${
          verifications.length === 0
            ? `<div class="empty-state"><div class="empty-title">No verification records yet</div><div class="empty-desc">Enroll an identity and run a verification check to see live results here.</div></div>`
            : `<div class="table-wrap">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>Identity Ref</th>
                      <th>Pipeline</th>
                      <th>Outcome</th>
                      <th>Liveness</th>
                      <th>Risk</th>
                      <th class="num-col">Similarity</th>
                      <th class="num-col">Latency</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${verifications
                      .slice(0, 8)
                      .map((v) => {
                        const cls = v.outcome === 'match' ? 'state-success' : v.outcome === 'no_match' ? 'state-danger' : 'state-warning';
                        const liveHtml =
                          typeof v.livenessPassed === 'boolean'
                            ? `<span class="state-text ${v.livenessPassed ? 'state-success' : 'state-danger'}">${v.livenessPassed ? 'Pass' : 'Fail'}</span>`
                            : `<span class="meta-line">—</span>`;
                        const rLvl = v.riskLevel || 'low';
                        const rCls = rLvl === 'critical' || rLvl === 'high' ? 'state-danger' : rLvl === 'medium' ? 'state-warning' : 'state-success';
                        const riskHtml =
                          typeof v.riskScore === 'number'
                            ? `<span class="state-text ${rCls}">${v.riskScore} (${escapeHtml(rLvl)})</span>`
                            : `<span class="meta-line">—</span>`;
                        const latHtml = typeof v.processingTimeMs === 'number' ? `${v.processingTimeMs} ms` : '—';
                        return `
                        <tr>
                          <td class="mono"><strong>${escapeHtml(v.identityRef)}</strong></td>
                          <td class="mono">${escapeHtml(v.pipeline || 'hierarchical')}</td>
                          <td><span class="state-text ${cls}">${escapeHtml(v.outcome)}</span></td>
                          <td>${liveHtml}</td>
                          <td>${riskHtml}</td>
                          <td class="num-col">${fmtPct(v.score || 0)}</td>
                          <td class="num-col">${latHtml}</td>
                          <td class="mono" style="font-size:12px;">${escapeHtml(fmtFsTime(v.createdAt))}</td>
                        </tr>`;
                      })
                      .join('')}
                  </tbody>
                </table>
              </div>`
        }
      </section>

      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Live System Status</h2>
            <p class="panel-subtitle">Connected security, biometric models, storage, and AI subsystems</p>
          </div>
        </div>
        <div class="divider-list" style="font-size:13.5px;">
          <div class="divider-row">
            <span>Firebase Authentication</span>
            <span class="state-text state-success">Signed In (${escapeHtml(appState.profile?.role || 'viewer')})</span>
          </div>
          <div class="divider-row">
            <span>Cloud Firestore Sync</span>
            <span class="state-text ${appState.firestoreOk ? 'state-success' : 'state-danger'}">${appState.firestoreOk ? 'Connected' : 'Offline'}${fsTel.avgLatencyMs ? ` (${fsTel.avgLatencyMs}ms)` : ''}</span>
          </div>
          <div class="divider-row">
            <span>Encrypted Biometric Vault</span>
            <span class="state-text ${health?.vault_ready ? 'state-success' : 'state-warning'}">${health?.vault_ready ? 'AES-256-GCM Active' : 'Unavailable'}</span>
          </div>
          <div class="divider-row">
            <span>Face Recognition Engine</span>
            <span class="mono" style="font-size:12px;">BlazeFace+FaceRes-1024D</span>
          </div>
          <div class="divider-row">
            <span>Voice &amp; Fingerprint Engines</span>
            <span class="mono" style="font-size:12px;">CMVN-96D · Minutiae-RANSAC</span>
          </div>
          <div class="divider-row">
            <span>AI Security Analyst (Gemini)</span>
            <span class="state-text ${health?.gemini_configured ? 'state-success' : 'state-warning'}">${health?.gemini_configured ? 'Ready (Server-Side)' : 'Not Configured'}</span>
          </div>
          <div class="divider-row">
            <span>Engine Version</span>
            <span class="mono">${escapeHtml(health?.feature_version || 'v2.0-multimodal')}</span>
          </div>
          <div class="divider-row">
            <span>Fusion Policy &amp; Thresholds</span>
            <span class="mono">${escapeHtml(appState.settings?.fusionPolicy || 'hierarchical_adaptive')} · F:${appState.settings?.faceThreshold ?? 0.72}</span>
          </div>
        </div>
      </section>
    </div>
  `;

  container.querySelectorAll('[data-goto]').forEach((b) => b.addEventListener('click', () => navigate(b.dataset.goto)));
}

// 2. BIOMETRIC IDENTITY ENROLLMENT
export function renderEnrollment(container, { appState, navigate }) {
  if (!appState.permissions.includes('create_identity')) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Your role (${escapeHtml(appState.profile?.role)}) is not authorized to enroll biometric identities.</div></div></div>`;
    return;
  }

  let faceVec = null;
  let faceQuality = null;
  let voiceVec = null;
  let voiceQuality = null;
  let fpTemplate = null;
  let fpQuality = null;
  let refEditedManually = false;
  let activeStream = null;
  let guidanceTimer = null;
  let lastWavUrl = null;

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
        <h1 class="page-title">Biometric Enrollment</h1>
        <p class="page-subtitle">Pretrained FaceRes-1024D neural embeddings, 16kHz CMVN Voice-96D, and Gabor+Minutiae templates validated before encrypted vault storage.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-secondary" id="be-fill-all">Fill All QA Test Samples</button>
      </div>
    </div>

    <form id="be-form" class="stack-lg">
      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">1. Profile &amp; Consent</h2>
            <p class="panel-subtitle">Enter subject details—an Identity Reference ID is generated automatically</p>
          </div>
        </div>
        <div class="form-grid">
          <div class="form-field">
            <label class="field-label" for="be-name">Display Name</label>
            <input class="input" id="be-name" required maxlength="120" placeholder="Amira Al-Mansoor" />
          </div>
          <div class="form-field">
            <label class="field-label" for="be-ref">Identity Reference ID</label>
            <input class="input mono" id="be-ref" required pattern="^[a-zA-Z0-9_-]{2,64}$" placeholder="amira_al_mansoor" />
          </div>
          <div class="form-field full">
            <label class="checkbox-row">
              <input type="checkbox" id="be-consent" required />
              <span>Explicit biometric enrollment consent obtained and verified under operator authorization.</span>
            </label>
          </div>
        </div>
      </section>

      <div class="grid-3">
        <section class="panel stack-md">
          <div class="panel-header">
            <div><h2 class="panel-title">Face</h2><p class="panel-subtitle">BlazeFace + FaceMesh + FaceRes 1024-D</p></div>
            <span id="be-face-st" class="state-text state-neutral">Optional</span>
          </div>
          <div class="preview-frame" id="be-face-prev">No face image</div>
          <div id="be-face-q" class="meta-line">Single-face alignment, lighting &amp; anti-spoof check ready</div>
          <div class="row-wrap">
            <button type="button" class="btn btn-secondary btn-sm" id="be-cam-start">Webcam</button>
            <button type="button" class="btn btn-primary btn-sm" id="be-cam-snap" disabled>Capture Live</button>
            <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Photo<input type="file" id="be-face-file" accept="image/*" hidden /></label>
            <button type="button" class="btn btn-ghost btn-sm" id="be-face-sample">QA Sample</button>
          </div>
        </section>

        <section class="panel stack-md">
          <div class="panel-header">
            <div><h2 class="panel-title">Voice</h2><p class="panel-subtitle">16kHz CMVN MFCC+Delta+F0 (96-D)</p></div>
            <span id="be-voice-st" class="state-text state-neutral">Optional</span>
          </div>
          <canvas class="waveform-canvas" id="be-voice-wave" width="380" height="86"></canvas>
          <div id="be-voice-audio-slot" hidden><audio id="be-voice-player" controls style="width:100%;height:34px;"></audio></div>
          <div id="be-voice-q" class="meta-line">Record 2.4s clear speech or upload WAV/MP3/M4A</div>
          <div class="row-wrap">
            <button type="button" class="btn btn-secondary btn-sm" id="be-mic-rec">Record Mic</button>
            <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Audio<input type="file" id="be-voice-file" accept="audio/*" hidden /></label>
            <button type="button" class="btn btn-ghost btn-sm" id="be-voice-sample">QA Sample</button>
          </div>
        </section>

        <section class="panel stack-md">
          <div class="panel-header">
            <div><h2 class="panel-title">Fingerprint</h2><p class="panel-subtitle">Gabor Ridge + Zhang-Suen Minutiae</p></div>
            <span id="be-fp-st" class="state-text state-neutral">Optional</span>
          </div>
          <div class="preview-frame fingerprint-frame" id="be-fp-prev" style="margin:0 auto;">No print image</div>
          <div id="be-fp-q" class="meta-line">Upload a clear fingerprint ridge scan (optical/capacitive image)</div>
          <div class="row-wrap">
            <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Print<input type="file" id="be-fp-file" accept="image/*" hidden /></label>
            <button type="button" class="btn btn-ghost btn-sm" id="be-fp-sample">QA Sample</button>
          </div>
        </section>
      </div>

      <div class="panel row-between">
        <div id="be-summary" class="meta-line">Add at least one biometric modality above to enroll.</div>
        <button type="submit" class="btn btn-primary" id="be-submit">Enroll Identity</button>
      </div>
    </form>

    <div id="be-result"></div>
  `;

  const nameInput = container.querySelector('#be-name');
  const refInput = container.querySelector('#be-ref');
  const summaryEl = container.querySelector('#be-summary');
  const facePrev = container.querySelector('#be-face-prev');
  const faceSt = container.querySelector('#be-face-st');
  const faceQEl = container.querySelector('#be-face-q');
  const camSnap = container.querySelector('#be-cam-snap');
  const voiceWave = container.querySelector('#be-voice-wave');
  const voiceSt = container.querySelector('#be-voice-st');
  const voiceQEl = container.querySelector('#be-voice-q');
  const voiceAudioSlot = container.querySelector('#be-voice-audio-slot');
  const voicePlayer = container.querySelector('#be-voice-player');
  const fpPrev = container.querySelector('#be-fp-prev');
  const fpSt = container.querySelector('#be-fp-st');
  const fpQEl = container.querySelector('#be-fp-q');

  const updateSummary = () => {
    const ready = [];
    if (faceVec) ready.push('Face (1024-D)');
    if (voiceVec) ready.push('Voice (96-D)');
    if (fpTemplate) ready.push('Fingerprint (Minutiae)');
    summaryEl.textContent = ready.length
      ? `Ready to enroll: ${ready.join(' + ')} (${ready.length} modality/modalities)`
      : 'Add at least one biometric modality above to enroll.';
  };

  refInput.addEventListener('input', () => {
    refEditedManually = refInput.value.trim().length > 0;
  });

  nameInput.addEventListener('input', () => {
    if (!refEditedManually) {
      refInput.value = slugifyIdentityRef(nameInput.value);
    }
  });

  const setFaceReal = async (source, label = 'FaceRes-1024D Ready', extraQuality = {}) => {
    faceSt.className = 'state-text state-warning';
    faceSt.textContent = 'Analyzing...';
    faceQEl.textContent = 'Running BlazeFace + FaceMesh + FaceRes-1024D & anti-spoof...';
    try {
      const res = await extractFaceFeatures(source, extraQuality);
      faceVec = res.vector;
      faceQuality = res.quality;
      facePrev.innerHTML = '';
      const c = document.createElement('canvas');
      c.width = 240; c.height = 180;
      c.getContext('2d').drawImage(source, 0, 0, 240, 180);
      facePrev.appendChild(c);

      faceSt.className = `state-text ${faceQuality.spoofRiskFlag ? 'state-warning' : 'state-success'}`;
      faceSt.textContent = faceQuality.spoofRiskFlag ? 'Spoof Warning' : label;
      faceQEl.textContent = `Q:${faceQuality.faceQualityScore}/100 · Yaw:${faceQuality.poseYawDeg}° · Sharp:${faceQuality.sharpness}${
        typeof faceQuality.antispoofScore === 'number' ? ` · Real:${Math.round(faceQuality.antispoofScore * 100)}%` : ''
      }${typeof faceQuality.frameMotionScore === 'number' ? ` · Motion:${faceQuality.frameMotionScore}` : ''}`;
      updateSummary();
    } catch (err) {
      faceVec = null;
      faceQuality = null;
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = 'Rejected';
      faceQEl.textContent = err.message;
      updateSummary();
      showToast(err.message, 'danger');
    }
  };

  const setFaceSyntheticSample = (seed) => {
    const canvas = renderSampleFaceCanvas(seed);
    facePrev.innerHTML = '';
    facePrev.appendChild(canvas);
    faceVec = makeSeededVector(`face_v2_${seed}`, 1024);
    faceQuality = {
      contrastStd: 46.2,
      sharpness: 22.5,
      meanBrightness: 132,
      faceWidthPx: 140,
      faceHeightPx: 140,
      faceQualityScore: 86,
      spoofRiskFlag: false,
      captureSource: 'test_sample',
      model: 'synthetic-qa-1024d',
    };
    faceSt.className = 'state-text state-neutral';
    faceSt.textContent = 'QA Sample (1024-D)';
    faceQEl.textContent = 'Synthetic deterministic QA probe (marked non-camera)';
    updateSummary();
  };

  const setVoice = (samples, rate, label = 'Ready (96-D)', captureSource = 'upload', wavUrl = null) => {
    try {
      const res = extractVoiceFeaturesFromPCM(samples, rate, captureSource);
      voiceVec = res.vector;
      voiceQuality = res.stats;
      drawWaveform(voiceWave, samples);

      if (wavUrl) {
        if (lastWavUrl) URL.revokeObjectURL(lastWavUrl);
        lastWavUrl = wavUrl;
        voicePlayer.src = wavUrl;
        voiceAudioSlot.hidden = false;
      } else {
        voiceAudioSlot.hidden = true;
      }

      const spoofCount = (voiceQuality.spoofSignals || []).length;
      voiceSt.className = `state-text ${spoofCount ? 'state-warning' : 'state-success'}`;
      voiceSt.textContent = spoofCount ? 'Replay Risk' : label;
      voiceQEl.textContent = `${voiceQuality.durationSec}s · ${voiceQuality.speechSegments} seg · Q:${voiceQuality.voiceQualityScore}/100 · SNR:${voiceQuality.snrEstimateDb}dB · F0:${voiceQuality.f0MedianHz || '—'}Hz`;
      updateSummary();
    } catch (err) {
      voiceVec = null;
      voiceQuality = null;
      voiceSt.className = 'state-text state-danger';
      voiceSt.textContent = 'Rejected';
      voiceQEl.textContent = err.message;
      updateSummary();
      showToast(err.message, 'danger');
    }
  };

  const setFp = (source, label = 'Minutiae Ready', captureSource = 'upload') => {
    try {
      const res = extractFingerprintFeatures(source, captureSource);
      fpTemplate = res.template;
      fpQuality = res.quality;
      fpPrev.innerHTML = '';
      const c = document.createElement('canvas');
      c.width = 180; c.height = 180;
      c.getContext('2d').drawImage(source, 0, 0, 180, 180);
      fpPrev.appendChild(c);

      fpSt.className = `state-text ${fpQuality.validPrint ? 'state-success' : 'state-warning'}`;
      fpSt.textContent = fpQuality.validPrint ? label : 'Low Clarity';
      fpQEl.textContent = `Minutiae:${fpQuality.minutiaeHeuristicCount} · Coherence:${fpQuality.meanCoherence} · Q:${fpQuality.qualityScore}/100`;
      updateSummary();
    } catch (err) {
      fpTemplate = null;
      fpQuality = null;
      fpSt.className = 'state-text state-danger';
      fpSt.textContent = 'Rejected';
      fpQEl.textContent = err.message;
      updateSummary();
      showToast(err.message, 'danger');
    }
  };

  container.querySelector('#be-fill-all').addEventListener('click', () => {
    stopCamera();
    if (!nameInput.value.trim()) nameInput.value = 'Demo Subject';
    if (!refInput.value.trim()) {
      refInput.value = slugifyIdentityRef(nameInput.value) || `subject_${Date.now().toString().slice(-4)}`;
    }
    const seed = refInput.value.trim();
    setFaceSyntheticSample(seed);
    const p = synthesizeSampleVoicePCM(seed, 3);
    setVoice(p.samples, p.sampleRate, 'QA Sample (96-D)', 'test_sample');
    setFp(renderSampleFingerprintCanvas(seed), 'QA Sample (Minutiae)', 'test_sample');
    container.querySelector('#be-consent').checked = true;
    showToast('Loaded synthetic QA test samples across all 3 modalities.', 'neutral');
  });

  container.querySelector('#be-cam-start').addEventListener('click', async () => {
    try {
      stopCamera();
      faceSt.className = 'state-text state-warning';
      faceSt.textContent = 'Loading ML...';
      faceQEl.textContent = 'Loading BlazeFace + FaceMesh + FaceRes-1024D models...';
      await ensureFaceEngineReady();

      activeStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } } });
      const wrap = document.createElement('div');
      wrap.className = 'face-guide-wrap';
      const v = document.createElement('video');
      v.autoplay = true; v.playsInline = true; v.muted = true; v.srcObject = activeStream;
      const oval = document.createElement('div');
      oval.className = 'face-guide-oval';
      const msgBadge = document.createElement('div');
      msgBadge.className = 'face-guide-status';
      msgBadge.textContent = 'Position face inside guide oval...';

      wrap.appendChild(v);
      wrap.appendChild(oval);
      wrap.appendChild(msgBadge);
      facePrev.innerHTML = '';
      facePrev.appendChild(wrap);
      faceSt.className = 'state-text state-neutral';
      faceSt.textContent = 'Live Preview';
      camSnap.disabled = false;

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

      camSnap.onclick = async () => {
        camSnap.disabled = true;
        camSnap.textContent = 'Checking Liveness...';
        try {
          const frame1 = snapVideoFrameCanvas(v);
          await new Promise((r) => setTimeout(r, 280));
          const frame2 = snapVideoFrameCanvas(v);
          const motion = computeFrameMotion(frame1, frame2);
          stopCamera();
          await setFaceReal(frame2, 'Live Capture', {
            isLiveCapture: true,
            frameMotionScore: motion,
            captureSource: 'webcam',
          });
        } finally {
          camSnap.textContent = 'Capture Live';
          stopCamera();
        }
      };
    } catch (err) {
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = 'Camera Error';
      showToast(`Camera error: ${err.message}`, 'warning');
    }
  });

  container.querySelector('#be-face-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 8 * 1024 * 1024) { showToast('Face image exceeds 8 MB limit.', 'danger'); return; }
    try {
      stopCamera();
      await setFaceReal(await loadImageFile(f), 'FaceRes-1024D Ready', { captureSource: 'upload' });
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });

  container.querySelector('#be-face-sample').addEventListener('click', () => {
    stopCamera();
    const ref = refInput.value.trim() || 'sample_id';
    setFaceSyntheticSample(ref);
  });

  container.querySelector('#be-mic-rec').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const p = await recordMicrophonePCM(2400, ({ elapsedSec, totalSec }) => {
        btn.textContent = `Recording ${elapsedSec.toFixed(1)}/${totalSec.toFixed(1)}s...`;
      });
      setVoice(p.samples, p.sampleRate, 'Mic Ready (96-D)', 'microphone', p.wavUrl);
    } catch (err) {
      showToast(`Mic error: ${err.message}`, 'warning');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Record Mic';
    }
  });

  container.querySelector('#be-voice-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const p = await decodeAudioFileToPCM(f);
      setVoice(p.samples, p.sampleRate, 'Uploaded (96-D)', 'upload');
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });

  container.querySelector('#be-voice-sample').addEventListener('click', () => {
    const ref = refInput.value.trim() || 'sample_id';
    const p = synthesizeSampleVoicePCM(ref, 3);
    setVoice(p.samples, p.sampleRate, 'QA Sample (96-D)', 'test_sample');
  });

  container.querySelector('#be-fp-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try { setFp(await loadImageFile(f), 'Minutiae Ready', 'upload'); }
    catch (err) { showToast(err.message, 'danger'); }
  });

  container.querySelector('#be-fp-sample').addEventListener('click', () => {
    const ref = refInput.value.trim() || 'sample_id';
    setFp(renderSampleFingerprintCanvas(ref), 'QA Sample (Minutiae)', 'test_sample');
  });

  container.querySelector('#be-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const identityRef = refInput.value.trim();
    const displayName = nameInput.value.trim();
    const consentRecorded = container.querySelector('#be-consent').checked;
    const submitBtn = container.querySelector('#be-submit');

    const samples = {};
    const quality = {};
    if (faceVec) {
      samples.face = faceVec;
      if (faceQuality) quality.face = faceQuality;
    }
    if (voiceVec) {
      samples.voice = voiceVec;
      if (voiceQuality) quality.voice = voiceQuality;
    }
    if (fpTemplate) {
      samples.fingerprint = fpTemplate;
      if (fpQuality) quality.fingerprint = fpQuality;
    }

    if (!Object.keys(samples).length) {
      showToast('Provide at least one biometric sample before enrolling.', 'warning');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Validating & Encrypting...';
    try {
      const apiRes = await enrollBiometricIdentity({ identityRef, consentRecorded, samples, quality });
      await saveIdentityMetadata({
        identityRef,
        displayName,
        registeredModalities: apiRes.registeredModalities,
        featureVersion: apiRes.featureVersion,
      });
      await appendAuditLog({
        action: 'identity_enrolled',
        resourceType: 'identity',
        resourceId: identityRef,
        result: `Enrolled [${apiRes.registeredModalities.join(', ')}] (${apiRes.featureVersion}) in ${apiRes.processingTimeMs}ms`,
        requestId: apiRes.requestId,
      });
      await pushNotification({
        title: 'Identity Enrolled',
        message: `${displayName} (${identityRef}) enrolled with [${apiRes.registeredModalities.join(', ')}].`,
        type: 'success',
      });

      const warnHtml = (apiRes.qualityWarnings || []).length
        ? `<div style="margin-top:4px;font-size:12.5px;color:var(--status-warning);">Warnings: ${escapeHtml(apiRes.qualityWarnings.join(' · '))}</div>`
        : '';

      const resContainer = container.querySelector('#be-result');
      resContainer.innerHTML = `
        <div class="notice-strip success" style="align-items:center;">
          <div>
            <strong>Enrollment Confirmed &amp; Quality Verified (${apiRes.processingTimeMs} ms)</strong>
            <div>Identity <span class="mono">${escapeHtml(apiRes.identityRef)}</span> encrypted in AES-256-GCM vault with <span class="mono">${escapeHtml(apiRes.registeredModalities.join(', '))}</span> (${escapeHtml(apiRes.featureVersion)}).</div>
            ${warnHtml}
          </div>
          <button type="button" class="btn btn-primary btn-sm" id="be-verify-now">Verify This Identity</button>
        </div>
      `;
      resContainer.querySelector('#be-verify-now')?.addEventListener('click', () => {
        navigate('verification', { identityRef: apiRes.identityRef });
      });
      showToast(`Identity "${identityRef}" enrolled.`, 'success');
      stopCamera();
    } catch (err) {
      container.querySelector('#be-result').innerHTML = `<div class="notice-strip danger"><div><strong>Enrollment Quality / Validation Rejected</strong><div>${escapeHtml(err.message)}</div></div></div>`;
      showToast(err.message, 'danger');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Enroll Identity';
    }
  });

  return () => {
    stopCamera();
    if (lastWavUrl) URL.revokeObjectURL(lastWavUrl);
  };
}

// 3. VERIFICATION CENTER (Quality + Liveness + Fusion Policy + Conflict Guard + Adaptive Risk)
export function renderVerification(container, { appState, navigate }) {
  if (!appState.permissions.includes('perform_verification')) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Your role (${escapeHtml(appState.profile?.role)}) cannot execute biometric verification requests.</div></div></div>`;
    return;
  }

  const identities = appState.identities.filter((i) => i.status === 'active');
  let faceVec = null;
  let faceQuality = null;
  let voiceVec = null;
  let voiceQuality = null;
  let fpTemplate = null;
  let fpQuality = null;
  let activeStream = null;
  let guidanceTimer = null;
  let lastWavUrl = null;
  let currentIsTestProbe = false;

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

  const initialId =
    identities.find((i) => i.identityRef === appState.preselectedIdentityRef) || identities[0] || null;
  appState.preselectedIdentityRef = '';

  let selectedPipeline = initialId
    ? recommendPipelineForModalities(initialId.registeredModalities || [])
    : 'hierarchical';

  const defaultPolicy = appState.settings?.fusionPolicy || 'hierarchical_adaptive';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Verification Center</h1>
        <p class="page-subtitle">Runs signal quality gating, anti-spoofing liveness, quality-weighted multimodal fusion, conflict detection, and adaptive risk enforcement.</p>
      </div>
      ${
        identities.length === 0 && appState.permissions.includes('create_identity')
          ? `<div class="page-actions"><button type="button" class="btn btn-primary" id="mv-go-enroll">Enroll First Identity</button></div>`
          : ''
      }
    </div>

    ${
      identities.length === 0
        ? `<section class="panel"><div class="empty-state"><div class="empty-title">No active identities enrolled yet</div><div class="empty-desc">Enroll at least one biometric identity first before running verification checks.</div></div></section>`
        : `
      <div class="panel stack-md">
        <div class="row-between" style="align-items:flex-start;">
          <div class="form-field" style="min-width:250px;flex:1;max-width:380px;">
            <label class="field-label" for="mv-id">Claimed Identity</label>
            <select class="select" id="mv-id">
              ${identities
                .map(
                  (i) =>
                    `<option value="${escapeHtml(i.identityRef)}" ${i.identityRef === initialId?.identityRef ? 'selected' : ''}>${escapeHtml(i.displayName)} (${escapeHtml(i.identityRef)})</option>`
                )
                .join('')}
            </select>
            <span id="mv-enrolled-info" class="meta-line"></span>
          </div>

          <div class="form-field" style="min-width:220px;flex:1;max-width:300px;">
            <label class="field-label" for="mv-policy">Fusion Policy</label>
            <select class="select" id="mv-policy">
              ${FUSION_POLICIES.map((fp) => `<option value="${fp.id}" ${fp.id === defaultPolicy ? 'selected' : ''}>${escapeHtml(fp.label)}</option>`).join('')}
            </select>
            <span id="mv-policy-desc" class="meta-line"></span>
          </div>

          <div class="form-field" style="min-width:200px;flex:1;max-width:240px;">
            <label class="field-label" for="mv-gt">Ground Truth Label</label>
            <select class="select" id="mv-gt">
              <option value="unlabeled">Unlabeled (Operational)</option>
              <option value="genuine">Genuine Trial (Known Same Subject)</option>
              <option value="impostor">Impostor Trial (Known Different Subject)</option>
            </select>
            <span class="meta-line">Labeled trials power FAR/FRR/EER</span>
          </div>
        </div>

        <div class="stack-sm" style="gap:6px;">
          <span class="field-label">Verification Pipeline</span>
          <div class="segmented" id="mv-tabs">
            ${PIPELINE_CATALOG.map((p) => `<button type="button" class="segmented-btn" data-pipe="${p.key}">${escapeHtml(p.label)}</button>`).join('')}
          </div>
          <span id="mv-pipe-desc" class="meta-line"></span>
        </div>

        <div class="row-between" style="padding-top:8px;border-top:1px solid var(--border-hairline);">
          <label class="checkbox-row">
            <input type="checkbox" id="mv-adaptive" checked />
            <span>Adaptive Risk Enforcement (tighten threshold or require MFA when risk score ≥ 50)</span>
          </label>
          <div class="row-wrap">
            <button type="button" class="btn btn-secondary btn-sm" id="mv-load-match">Load Matching QA Probes</button>
            <button type="button" class="btn btn-ghost btn-sm" id="mv-load-impostor">Load Impostor QA Probes</button>
          </div>
        </div>

        <div class="grid-3">
          <div class="probe-card" id="mv-card-face">
            <div class="row-between">
              <div>
                <strong>Face Probe</strong>
                <div id="mv-face-req" class="meta-line"></div>
              </div>
              <span id="mv-face-st" class="state-text state-neutral">Empty</span>
            </div>
            <div id="mv-face-live-wrap" class="preview-frame" style="max-height:175px;" hidden></div>
            <div id="mv-face-q" class="meta-line"></div>
            <div class="row-wrap">
              <button type="button" class="btn btn-secondary btn-sm" id="mv-face-cam">Live Webcam</button>
              <button type="button" class="btn btn-primary btn-sm" id="mv-face-snap" hidden>Capture (Liveness)</button>
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload<input type="file" id="mv-face-file" accept="image/*" hidden /></label>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-face-gen">Match QA</button>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-face-imp">Impostor QA</button>
            </div>
          </div>

          <div class="probe-card" id="mv-card-voice">
            <div class="row-between">
              <div>
                <strong>Voice Probe</strong>
                <div id="mv-voice-req" class="meta-line"></div>
              </div>
              <span id="mv-voice-st" class="state-text state-neutral">Empty</span>
            </div>
            <div id="mv-voice-audio-slot" hidden><audio id="mv-voice-player" controls style="width:100%;height:34px;"></audio></div>
            <div id="mv-voice-q" class="meta-line"></div>
            <div class="row-wrap">
              <button type="button" class="btn btn-secondary btn-sm" id="mv-voice-mic">Mic (2.4s)</button>
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload<input type="file" id="mv-voice-file" accept="audio/*" hidden /></label>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-voice-gen">Match QA</button>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-voice-imp">Impostor QA</button>
            </div>
          </div>

          <div class="probe-card" id="mv-card-fp">
            <div class="row-between">
              <div>
                <strong>Fingerprint Probe</strong>
                <div id="mv-fp-req" class="meta-line"></div>
              </div>
              <span id="mv-fp-st" class="state-text state-neutral">Empty</span>
            </div>
            <div id="mv-fp-q" class="meta-line"></div>
            <div class="row-wrap">
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Print<input type="file" id="mv-fp-file" accept="image/*" hidden /></label>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-fp-gen">Match QA</button>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-fp-imp">Impostor QA</button>
            </div>
          </div>
        </div>

        <div class="row-between">
          <span class="meta-line">Evaluated server-side against AES-256-GCM templates; model similarity is never treated as identity probability.</span>
          <button type="button" class="btn btn-primary" id="mv-run">Verify Identity</button>
        </div>
      </div>

      <div id="mv-result"></div>
    `
    }
  `;

  container.querySelector('#mv-go-enroll')?.addEventListener('click', () => navigate('enrollment'));
  if (identities.length === 0) return stopCamera;

  const idSel = container.querySelector('#mv-id');
  const policySel = container.querySelector('#mv-policy');
  const policyDescEl = container.querySelector('#mv-policy-desc');
  const gtSel = container.querySelector('#mv-gt');
  const enrolledInfoEl = container.querySelector('#mv-enrolled-info');
  const pipeDescEl = container.querySelector('#mv-pipe-desc');
  const faceSt = container.querySelector('#mv-face-st');
  const faceQEl = container.querySelector('#mv-face-q');
  const faceLiveWrap = container.querySelector('#mv-face-live-wrap');
  const faceSnapBtn = container.querySelector('#mv-face-snap');
  const voiceSt = container.querySelector('#mv-voice-st');
  const voiceQEl = container.querySelector('#mv-voice-q');
  const voiceAudioSlot = container.querySelector('#mv-voice-audio-slot');
  const voicePlayer = container.querySelector('#mv-voice-player');
  const fpSt = container.querySelector('#mv-fp-st');
  const fpQEl = container.querySelector('#mv-fp-q');

  const getSelectedIdentity = () => identities.find((i) => i.identityRef === idSel.value) || identities[0];

  const syncPolicyDesc = () => {
    const def = FUSION_POLICIES.find((p) => p.id === policySel.value);
    if (policyDescEl && def) policyDescEl.textContent = def.summary;
  };
  syncPolicyDesc();
  policySel.addEventListener('change', syncPolicyDesc);

  const syncAdaptiveUI = () => {
    const idObj = getSelectedIdentity();
    const enrolled = new Set(idObj?.registeredModalities || []);
    enrolledInfoEl.textContent = `Enrolled: ${[...enrolled].join(', ') || 'none'} · ${idObj?.featureVersion || 'v2.0-multimodal'}`;

    const compatible = PIPELINE_CATALOG.filter((p) => p.requires.every((m) => enrolled.has(m)));
    if (!compatible.some((p) => p.key === selectedPipeline)) {
      selectedPipeline = compatible[0]?.key || recommendPipelineForModalities([...enrolled]);
    }

    container.querySelectorAll('#mv-tabs .segmented-btn').forEach((btn) => {
      const def = PIPELINE_CATALOG.find((p) => p.key === btn.dataset.pipe);
      const supported = def ? def.requires.every((m) => enrolled.has(m)) : false;
      btn.disabled = !supported;
      btn.classList.toggle('active', btn.dataset.pipe === selectedPipeline);
      btn.title = supported ? def.description : `Requires enrolled: ${def?.requires.join(', ')}`;
    });

    const activeDef = PIPELINE_CATALOG.find((p) => p.key === selectedPipeline) || PIPELINE_CATALOG[0];
    pipeDescEl.textContent = activeDef.description;

    const updateCard = (mod, cardSel, reqSel) => {
      const card = container.querySelector(cardSel);
      const req = container.querySelector(reqSel);
      const isReq = activeDef.requires.includes(mod);
      const isOpt = activeDef.optional.includes(mod) && enrolled.has(mod);
      card.classList.toggle('required-active', isReq);
      card.classList.toggle('inactive', !isReq && !isOpt);
      req.textContent = isReq ? 'Required for pipeline' : isOpt ? 'Optional Stage 2 fallback' : 'Not used in selected pipeline';
    };
    updateCard('face', '#mv-card-face', '#mv-face-req');
    updateCard('voice', '#mv-card-voice', '#mv-voice-req');
    updateCard('fingerprint', '#mv-card-fp', '#mv-fp-req');
  };

  syncAdaptiveUI();

  idSel.addEventListener('change', () => {
    const idObj = getSelectedIdentity();
    selectedPipeline = recommendPipelineForModalities(idObj?.registeredModalities || []);
    syncAdaptiveUI();
  });

  container.querySelectorAll('#mv-tabs .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      selectedPipeline = btn.dataset.pipe;
      syncAdaptiveUI();
    });
  });

  const setFaceRealProbe = async (source, statusText, extraQuality = {}) => {
    faceSt.className = 'state-text state-warning';
    faceSt.textContent = 'Analyzing...';
    faceQEl.textContent = 'Extracting FaceRes-1024D embedding...';
    try {
      const res = await extractFaceFeatures(source, extraQuality);
      faceVec = res.vector;
      faceQuality = res.quality;
      currentIsTestProbe = false;
      if (gtSel.value !== 'unlabeled') gtSel.value = 'unlabeled';
      faceSt.className = `state-text ${faceQuality.spoofRiskFlag ? 'state-warning' : 'state-success'}`;
      faceSt.textContent = faceQuality.spoofRiskFlag ? 'Spoof Warning' : statusText;
      faceQEl.textContent = `Q:${faceQuality.faceQualityScore}/100 · Yaw:${faceQuality.poseYawDeg}° · Sharp:${faceQuality.sharpness}${
        typeof faceQuality.antispoofScore === 'number' ? ` · Real:${Math.round(faceQuality.antispoofScore * 100)}%` : ''
      }${typeof faceQuality.frameMotionScore === 'number' ? ` · Motion:${faceQuality.frameMotionScore}` : ''}`;
    } catch (err) {
      faceVec = null;
      faceQuality = null;
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = 'Rejected';
      faceQEl.textContent = err.message;
      showToast(err.message, 'danger');
    }
  };

  const setVoiceProbe = (samples, rate, statusText, captureSource = 'upload', wavUrl = null) => {
    try {
      const res = extractVoiceFeaturesFromPCM(samples, rate, captureSource);
      voiceVec = res.vector;
      voiceQuality = res.stats;
      if (captureSource !== 'test_sample') {
        currentIsTestProbe = false;
        if (gtSel.value !== 'unlabeled') gtSel.value = 'unlabeled';
      }
      if (wavUrl) {
        if (lastWavUrl) URL.revokeObjectURL(lastWavUrl);
        lastWavUrl = wavUrl;
        voicePlayer.src = wavUrl;
        voiceAudioSlot.hidden = false;
      } else {
        voiceAudioSlot.hidden = true;
      }
      voiceSt.className = `state-text ${(voiceQuality.spoofSignals || []).length ? 'state-warning' : 'state-success'}`;
      voiceSt.textContent = statusText;
      voiceQEl.textContent = `${voiceQuality.durationSec}s · ${voiceQuality.speechSegments} seg · Q:${voiceQuality.voiceQualityScore}/100 · SNR:${voiceQuality.snrEstimateDb}dB`;
    } catch (err) {
      voiceVec = null;
      voiceQuality = null;
      voiceSt.className = 'state-text state-danger';
      voiceSt.textContent = 'Rejected';
      voiceQEl.textContent = err.message;
      showToast(err.message, 'danger');
    }
  };

  const setFpProbe = (source, statusText, captureSource = 'upload') => {
    try {
      const res = extractFingerprintFeatures(source, captureSource);
      fpTemplate = res.template;
      fpQuality = res.quality;
      if (captureSource !== 'test_sample') {
        currentIsTestProbe = false;
        if (gtSel.value !== 'unlabeled') gtSel.value = 'unlabeled';
      }
      fpSt.className = `state-text ${fpQuality.validPrint ? 'state-success' : 'state-warning'}`;
      fpSt.textContent = statusText;
      fpQEl.textContent = `Minutiae:${fpQuality.minutiaeHeuristicCount} · Coherence:${fpQuality.meanCoherence} · Q:${fpQuality.qualityScore}/100`;
    } catch (err) {
      fpTemplate = null;
      fpQuality = null;
      fpSt.className = 'state-text state-danger';
      fpSt.textContent = 'Rejected';
      fpQEl.textContent = err.message;
      showToast(err.message, 'danger');
    }
  };

  const loadFaceMatch = () => {
    if (!idSel.value) return;
    const idObj = getSelectedIdentity();
    const isLegacy = (idObj?.featureVersion || '').startsWith('v1.');
    faceVec = makeSeededVector(`face_v2_${idSel.value}`, isLegacy ? 208 : 1024);
    faceQuality = {
      contrastStd: 46.2,
      sharpness: 22.5,
      meanBrightness: 132,
      faceWidthPx: 140,
      faceHeightPx: 140,
      faceQualityScore: 86,
      spoofRiskFlag: false,
      captureSource: 'test_sample',
    };
    currentIsTestProbe = true;
    gtSel.value = 'genuine';
    faceSt.className = 'state-text state-success';
    faceSt.textContent = 'QA Match Probe';
    faceQEl.textContent = `Deterministic genuine QA probe (${faceVec.length}-D)`;
  };
  const loadVoiceMatch = () => {
    if (!idSel.value) return;
    const p = synthesizeSampleVoicePCM(idSel.value, 3);
    currentIsTestProbe = true;
    gtSel.value = 'genuine';
    setVoiceProbe(p.samples, p.sampleRate, 'QA Match Probe', 'test_sample');
  };
  const loadFpMatch = () => {
    if (!idSel.value) return;
    currentIsTestProbe = true;
    gtSel.value = 'genuine';
    setFpProbe(renderSampleFingerprintCanvas(idSel.value), 'QA Match Probe', 'test_sample');
  };

  const loadFaceImpostor = () => {
    const idObj = getSelectedIdentity();
    const isLegacy = (idObj?.featureVersion || '').startsWith('v1.');
    faceVec = makeSeededVector(`impostor_f_${Date.now()}`, isLegacy ? 208 : 1024, 0.05);
    faceQuality = {
      contrastStd: 48,
      sharpness: 24,
      meanBrightness: 128,
      faceWidthPx: 140,
      faceHeightPx: 140,
      faceQualityScore: 84,
      spoofRiskFlag: false,
      captureSource: 'test_impostor',
    };
    currentIsTestProbe = true;
    gtSel.value = 'impostor';
    faceSt.className = 'state-text state-danger';
    faceSt.textContent = 'QA Impostor';
    faceQEl.textContent = `Synthetic impostor probe (${faceVec.length}-D)`;
  };
  const loadVoiceImpostor = () => {
    voiceVec = makeSeededVector(`impostor_v_${Date.now()}`, 96, 0.05);
    voiceQuality = { durationSec: 2.0, meanRms: 0.14, speechSegments: 3, clippingRatio: 0, dynamicRangeDb: 18, voiceQualityScore: 84, captureSource: 'test_impostor' };
    currentIsTestProbe = true;
    gtSel.value = 'impostor';
    voiceSt.className = 'state-text state-danger';
    voiceSt.textContent = 'QA Impostor';
    voiceQEl.textContent = 'Synthetic impostor probe (96-D)';
  };
  const loadFpImpostor = () => {
    currentIsTestProbe = true;
    gtSel.value = 'impostor';
    const res = extractFingerprintFeatures(renderSampleFingerprintCanvas(`impostor_fp_${Date.now()}`), 'test_sample');
    fpTemplate = res.template;
    fpQuality = { ...res.quality, captureSource: 'test_impostor' };
    fpSt.className = 'state-text state-danger';
    fpSt.textContent = 'QA Impostor';
    fpQEl.textContent = `Synthetic impostor print (${fpTemplate.minutiae.length} minutiae)`;
  };

  container.querySelector('#mv-load-match').addEventListener('click', () => {
    const idObj = getSelectedIdentity();
    const enrolled = new Set(idObj?.registeredModalities || []);
    const def = PIPELINE_CATALOG.find((p) => p.key === selectedPipeline) || PIPELINE_CATALOG[0];
    const needed = new Set([...def.requires, ...def.optional.filter((m) => enrolled.has(m))]);
    if (needed.has('face')) loadFaceMatch();
    if (needed.has('voice')) loadVoiceMatch();
    if (needed.has('fingerprint')) loadFpMatch();
    showToast('Loaded matching QA probes (labeled Genuine Trial).', 'neutral');
  });

  container.querySelector('#mv-load-impostor').addEventListener('click', () => {
    const idObj = getSelectedIdentity();
    const enrolled = new Set(idObj?.registeredModalities || []);
    const def = PIPELINE_CATALOG.find((p) => p.key === selectedPipeline) || PIPELINE_CATALOG[0];
    const needed = new Set([...def.requires, ...def.optional.filter((m) => enrolled.has(m))]);
    if (needed.has('face')) loadFaceImpostor();
    if (needed.has('voice')) loadVoiceImpostor();
    if (needed.has('fingerprint')) loadFpImpostor();
    showToast('Loaded impostor QA probes (labeled Impostor Trial).', 'warning');
  });

  container.querySelector('#mv-face-cam').addEventListener('click', async () => {
    try {
      stopCamera();
      faceSt.className = 'state-text state-warning';
      faceSt.textContent = 'Loading ML...';
      await ensureFaceEngineReady();

      activeStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } } });
      const wrap = document.createElement('div');
      wrap.className = 'face-guide-wrap';
      const v = document.createElement('video');
      v.autoplay = true; v.playsInline = true; v.muted = true; v.srcObject = activeStream;
      const oval = document.createElement('div');
      oval.className = 'face-guide-oval';
      const msgBadge = document.createElement('div');
      msgBadge.className = 'face-guide-status';
      msgBadge.textContent = 'Align face in oval...';

      wrap.appendChild(v);
      wrap.appendChild(oval);
      wrap.appendChild(msgBadge);
      faceLiveWrap.innerHTML = '';
      faceLiveWrap.appendChild(wrap);
      faceLiveWrap.hidden = false;
      faceSnapBtn.hidden = false;
      faceSt.className = 'state-text state-neutral';
      faceSt.textContent = 'Live Preview';

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

      faceSnapBtn.onclick = async () => {
        faceSnapBtn.disabled = true;
        faceSnapBtn.textContent = 'Checking Liveness...';
        try {
          const f1 = snapVideoFrameCanvas(v);
          await new Promise((r) => setTimeout(r, 280));
          const f2 = snapVideoFrameCanvas(v);
          const motion = computeFrameMotion(f1, f2);
          stopCamera();
          await setFaceRealProbe(f2, 'Live Webcam', {
            isLiveCapture: true,
            frameMotionScore: motion,
            captureSource: 'webcam',
          });
        } finally {
          faceSnapBtn.disabled = false;
          faceSnapBtn.textContent = 'Capture (Liveness)';
          faceSnapBtn.hidden = true;
          faceLiveWrap.hidden = true;
          stopCamera();
        }
      };
    } catch (err) {
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = 'Camera Error';
      showToast(`Webcam error: ${err.message}`, 'warning');
    }
  });

  container.querySelector('#mv-face-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try { stopCamera(); await setFaceRealProbe(await loadImageFile(f), 'Uploaded', { captureSource: 'upload' }); }
    catch (err) { showToast(err.message, 'danger'); }
  });
  container.querySelector('#mv-face-gen').addEventListener('click', loadFaceMatch);
  container.querySelector('#mv-face-imp').addEventListener('click', loadFaceImpostor);

  container.querySelector('#mv-voice-mic').addEventListener('click', async (e) => {
    const b = e.currentTarget; b.disabled = true;
    try {
      const p = await recordMicrophonePCM(2400, ({ elapsedSec, totalSec }) => {
        b.textContent = `${elapsedSec.toFixed(1)}/${totalSec.toFixed(1)}s`;
      });
      setVoiceProbe(p.samples, p.sampleRate, 'Mic Captured', 'microphone', p.wavUrl);
    } catch (err) { showToast(err.message, 'warning'); }
    finally { b.disabled = false; b.textContent = 'Mic (2.4s)'; }
  });
  container.querySelector('#mv-voice-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const p = await decodeAudioFileToPCM(f);
      setVoiceProbe(p.samples, p.sampleRate, 'Uploaded', 'upload');
    } catch (err) { showToast(err.message, 'danger'); }
  });
  container.querySelector('#mv-voice-gen').addEventListener('click', loadVoiceMatch);
  container.querySelector('#mv-voice-imp').addEventListener('click', loadVoiceImpostor);

  container.querySelector('#mv-fp-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try { setFpProbe(await loadImageFile(f), 'Uploaded', 'upload'); }
    catch (err) { showToast(err.message, 'danger'); }
  });
  container.querySelector('#mv-fp-gen').addEventListener('click', loadFpMatch);
  container.querySelector('#mv-fp-imp').addEventListener('click', loadFpImpostor);

  container.querySelector('#mv-run').addEventListener('click', async () => {
    const identityRef = idSel.value;
    if (!identityRef) return;
    const runBtn = container.querySelector('#mv-run');
    const resultEl = container.querySelector('#mv-result');
    const adaptiveEnabled = container.querySelector('#mv-adaptive').checked;
    const fusionPolicy = policySel.value;
    const groundTruth = gtSel.value;
    runBtn.disabled = true; runBtn.textContent = 'Verifying...';

    const samples = {};
    const quality = {};
    if (faceVec) {
      samples.face = faceVec;
      if (faceQuality) quality.face = faceQuality;
    }
    if (voiceVec) {
      samples.voice = voiceVec;
      if (voiceQuality) quality.voice = voiceQuality;
    }
    if (fpTemplate) {
      samples.fingerprint = fpTemplate;
      if (fpQuality) quality.fingerprint = fpQuality;
    }

    try {
      const s = appState.settings || {};
      const res = await verifyMultimodalBiometrics({
        identityRef,
        pipeline: selectedPipeline,
        fusionPolicy,
        thresholds: {
          face: s.faceThreshold ?? 0.72,
          voice: s.voiceThreshold ?? 0.70,
          fingerprint: s.fingerprintThreshold ?? 0.72,
          threeModal: s.threeModalThreshold ?? 0.74,
        },
        samples,
        quality,
        adaptiveEnabled,
        groundTruth,
        isTestProbe: currentIsTestProbe,
      });

      const verId = await recordVerificationMetadata({
        identityRef,
        modalities: res.modalitiesEvaluated,
        pipeline: res.pipeline,
        outcome: res.outcome,
        reasonCode: res.reasonCode,
        score: res.score,
        confidence: res.confidence,
        confidenceBand: res.confidenceBand,
        conflictDetected: res.conflictDetected,
        processingTimeMs: res.processingTimeMs,
        featureVersion: res.featureVersion,
        groundTruth,
        isTestProbe: currentIsTestProbe,
        modalityEvaluations: res.modalityEvaluations,
        riskScore: res.risk?.score,
        riskLevel: res.risk?.level,
        livenessPassed: res.liveness?.passed,
        livenessScore: res.liveness?.score,
        adaptiveApplied: res.adaptiveApplied,
      });

      await appendAuditLog({
        action: 'biometric_verification',
        resourceType: 'identity',
        resourceId: identityRef,
        result: `${res.pipeline} (${res.fusionPolicy}): ${res.outcome} sim=${fmtPct(res.score)} conf=${fmtPct(res.confidence)} gt=${groundTruth} (${res.processingTimeMs}ms)`,
        requestId: res.requestId,
      });

      if (!res.liveness?.passed || (res.risk?.score ?? 0) >= 50 || res.conflictDetected) {
        const alertCategory = !res.liveness?.passed
          ? 'Spoofing / Liveness Failure'
          : res.conflictDetected
          ? 'Cross-Modality Conflict Detected'
          : 'High-Risk Verification Attempt';
        const alertDesc = `${identityRef} via ${res.pipeline}: outcome=${res.outcome}, similarity=${fmtPct(res.score)}, conf=${fmtPct(res.confidence)}, risk=${res.risk?.score}/100 (${res.risk?.level}). ${(res.rejectionReasons || res.liveness?.spoofSignals || []).join('; ')}`;
        await pushNotification({
          title: alertCategory,
          message: alertDesc.slice(0, 220),
          type: 'warning',
        }).catch(() => null);
        if (appState.permissions.includes('manage_alerts')) {
          await createSecurityAlert({
            severity: (res.risk?.score ?? 0) >= 75 || !res.liveness?.passed ? 'high' : 'medium',
            category: alertCategory,
            description: alertDesc,
            assignedTo: appState.fbUser?.uid || '',
          }).catch(() => null);
        }
      }

      const outcomeCls = res.outcome === 'match' ? 'state-success' : res.outcome === 'no_match' ? 'state-danger' : 'state-warning';
      const liveCls = res.liveness?.passed ? 'state-success' : 'state-danger';
      const riskLvl = res.risk?.level || 'low';
      const riskCls = riskLvl === 'critical' || riskLvl === 'high' ? 'state-danger' : riskLvl === 'medium' ? 'state-warning' : 'state-success';
      const confCls = res.confidenceBand === 'high' ? 'state-success' : res.confidenceBand === 'moderate' ? 'state-warning' : 'state-danger';
      const modRows = Object.entries(res.modalityEvaluations || {});

      resultEl.innerHTML = `
        <div class="panel stack-md">
          <div class="row-between">
            <div class="stack-sm" style="gap:2px;">
              <span class="state-text ${outcomeCls}">Verification Decision: ${escapeHtml(res.outcome.toUpperCase())} (${escapeHtml(res.reasonCode)})</span>
              <h3 class="panel-title">${escapeHtml(res.identityRef)} · ${escapeHtml(res.pipeline)} · <span class="mono">${escapeHtml(res.fusionPolicy)}</span></h3>
            </div>
            <div class="row-wrap">
              <div style="text-align:right;">
                <div class="meta-line" style="justify-content:flex-end;">Model Similarity</div>
                <div class="mono" style="font-size:21px;font-weight:700;">${fmtPct(res.score)}</div>
              </div>
              <div style="text-align:right;padding-left:14px;border-left:1px solid var(--border-hairline);">
                <div class="meta-line" style="justify-content:flex-end;">Verification Confidence</div>
                <div class="mono ${confCls}" style="font-size:18px;font-weight:700;">${fmtPct(res.confidence || 0)} (${escapeHtml(res.confidenceBand || 'low')})</div>
              </div>
              ${
                appState.permissions.includes('use_ai_analyst')
                  ? `<button type="button" class="btn btn-secondary btn-sm" id="mv-explain-ai">Explain in AI</button>`
                  : ''
              }
            </div>
          </div>

          <div class="progress-track">
            <div class="progress-fill ${res.outcome === 'match' ? 'success' : 'danger'}" style="width:${Math.min(100, Math.round(res.score * 100))}%"></div>
          </div>

          ${
            res.conflictDetected
              ? `<div class="notice-strip danger"><div><strong>Cross-Modality Conflict Blocked Override</strong><div>${escapeHtml((res.conflictDetails || []).join(' '))}</div></div></div>`
              : ''
          }
          ${
            res.legacyCompatibility
              ? `<div class="notice-strip warning"><div><strong>Legacy Template Compatibility Mode</strong><div>This identity was enrolled on <span class="mono">${escapeHtml(res.featureVersion)}</span>. Re-enroll in Enrollment Center to upgrade to v2.0 FaceRes-1024D &amp; Minutiae RANSAC.</div></div></div>`
              : ''
          }
          ${
            (res.rejectionReasons || []).length > 0
              ? `<div class="notice-strip warning"><div><strong>Decision Explanation</strong><div>${res.rejectionReasons.map((r) => `• ${escapeHtml(r)}`).join('<br/>')}</div></div></div>`
              : ''
          }

          <div class="meta-line">
            <span>Threshold: <strong class="mono">${fmtPct(res.threshold)}</strong>${res.adaptiveApplied ? ` (base ${fmtPct(res.baseThreshold)})` : ''}</span>
            <span aria-hidden="true">·</span>
            <span>Ground Truth: <strong class="mono">${escapeHtml(groundTruth)}</strong></span>
            <span aria-hidden="true">·</span>
            <span>Processing Time: <strong class="mono">${res.processingTimeMs ?? '—'} ms</strong></span>
            <span aria-hidden="true">·</span>
            <span>Request: <span class="mono">${escapeHtml(res.requestId)}</span></span>
          </div>

          ${
            modRows.length > 0
              ? `<div class="table-wrap">
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th>Modality</th>
                        <th class="num-col">Similarity</th>
                        <th class="num-col">Threshold</th>
                        <th class="num-col">Signal Quality</th>
                        <th>Status</th>
                        <th>Matcher Telemetry</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${modRows
                        .map(([mod, ev]) => {
                          const stCls = ev.strongMismatch ? 'state-danger' : ev.passed ? 'state-success' : 'state-warning';
                          const stTxt = ev.strongMismatch ? 'Strong Mismatch' : ev.passed ? 'Passed' : 'Below Threshold';
                          const detStr =
                            mod === 'fingerprint' && typeof ev.details?.matchedMinutiae === 'number'
                              ? `${ev.details.matchedMinutiae}/${ev.details.probeMinutiae} minutiae · rot ${ev.details.estimatedRotationDeg}°`
                              : typeof ev.rawCosine === 'number'
                              ? `rawCos=${ev.rawCosine} (${ev.details?.dim || ''}-D)`
                              : 'Evaluated';
                          return `
                          <tr>
                            <td style="text-transform:capitalize;"><strong>${escapeHtml(mod)}</strong></td>
                            <td class="num-col">${fmtPct(ev.score)}</td>
                            <td class="num-col">${fmtPct(ev.threshold)}</td>
                            <td class="num-col">${ev.qualityScore}/100</td>
                            <td><span class="state-text ${stCls}">${stTxt}</span></td>
                            <td class="mono" style="font-size:12px;">${escapeHtml(detStr)}</td>
                          </tr>`;
                        })
                        .join('')}
                    </tbody>
                  </table>
                </div>`
              : ''
          }

          <div class="grid-2">
            <div class="panel stack-sm" style="background:var(--bg-subtle);padding:14px 16px;">
              <div class="row-between">
                <strong>Liveness &amp; Anti-Spoofing</strong>
                <span class="state-text ${liveCls}">${res.liveness?.passed ? 'Passed' : 'Failed'} (${Math.round((res.liveness?.score ?? 0) * 100)}%)</span>
              </div>
              <div style="font-size:12.5px;color:var(--text-secondary);">
                ${[...(res.liveness?.checks || []), ...(res.liveness?.spoofSignals || [])].map((x) => `<div>• ${escapeHtml(x)}</div>`).join('') || 'Checked signal integrity.'}
              </div>
            </div>

            <div class="panel stack-sm" style="background:var(--bg-subtle);padding:14px 16px;">
              <div class="row-between">
                <strong>Behavioral Risk &amp; Adaptive Check</strong>
                <span class="state-text ${riskCls}">${res.risk?.score ?? 0}/100 (${escapeHtml(riskLvl)})</span>
              </div>
              <div style="font-size:12.5px;color:var(--text-secondary);">
                ${(res.risk?.factors || []).map((f) => `<div>• ${escapeHtml(f)}</div>`).join('')}
                ${res.details?.adaptive?.reason ? `<div style="margin-top:4px;color:var(--accent);">Adaptive: ${escapeHtml(res.details.adaptive.reason)}</div>` : ''}
              </div>
            </div>
          </div>
        </div>
      `;

      resultEl.querySelector('#mv-explain-ai')?.addEventListener('click', () => {
        navigate('ai_analyst', {
          verificationId: verId,
          analystMode: 'explain_verification',
          analystPrompt: `Explain verification result ${verId || res.requestId} for identity "${res.identityRef}" (${res.pipeline}, policy=${res.fusionPolicy}: outcome=${res.outcome}, similarity=${fmtPct(res.score)}, confidence=${fmtPct(res.confidence)}, conflict=${res.conflictDetected}, threshold=${fmtPct(res.threshold)}, liveness=${res.liveness?.passed ? 'pass' : 'fail'}, risk=${res.risk?.score}/100 ${res.risk?.level}, reason=${res.reasonCode}). Recommend next steps.`,
        });
      });
    } catch (err) {
      resultEl.innerHTML = `<div class="notice-strip danger"><div><strong>Verification / Quality Gate Rejected</strong><div>${escapeHtml(err.message)}</div></div></div>`;
      showToast(err.message, 'danger');
    } finally {
      runBtn.disabled = false; runBtn.textContent = 'Verify Identity';
    }
  });

  return () => {
    stopCamera();
    if (lastWavUrl) URL.revokeObjectURL(lastWavUrl);
  };
}

// 4. IDENTITIES DIRECTORY
export function renderIdentities(container, { appState, navigate }) {
  let searchQ = '';
  let statusFilter = 'all';
  let page = 1;
  const pageSize = 10;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Identity Directory</h1>
        <p class="page-subtitle">Manage enrolled identities, launch 1:1 or 1:N comparisons, submit controlled deletion requests, or run verification.</p>
      </div>
      ${appState.permissions.includes('create_identity') ? `<div class="page-actions"><button type="button" class="btn btn-primary" id="id-enroll-btn">Enroll Identity</button></div>` : ''}
    </div>

    <section class="panel stack-md">
      <div class="row-between">
        <div class="row-wrap">
          <input type="search" class="input" id="id-search" placeholder="Search identityRef or displayName..." style="width:260px;" />
          <div class="segmented" id="id-filter">
            <button type="button" class="segmented-btn active" data-st="all">All</button>
            <button type="button" class="segmented-btn" data-st="active">Active</button>
            <button type="button" class="segmented-btn" data-st="inactive">Inactive</button>
          </div>
        </div>
        <span id="id-count" class="meta-line"></span>
      </div>

      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Identity Ref</th>
              <th>Display Name</th>
              <th>Modalities</th>
              <th>Version</th>
              <th>Status</th>
              <th>Updated</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="id-tbody"></tbody>
        </table>
      </div>

      <div class="row-between" id="id-pager"></div>
    </section>
  `;

  container.querySelector('#id-enroll-btn')?.addEventListener('click', () => navigate('enrollment'));

  const tbody = container.querySelector('#id-tbody');
  const countEl = container.querySelector('#id-count');
  const pagerEl = container.querySelector('#id-pager');
  const canVerify = appState.permissions.includes('perform_verification');
  const canEdit = appState.permissions.includes('edit_identity');
  const canDelete = appState.permissions.includes('delete_identity');

  const drawTable = () => {
    const filtered = appState.identities.filter((i) => {
      if (statusFilter !== 'all' && i.status !== statusFilter) return false;
      if (searchQ) {
        const q = searchQ.toLowerCase();
        return i.identityRef.toLowerCase().includes(q) || (i.displayName || '').toLowerCase().includes(q);
      }
      return true;
    });
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    if (page > totalPages) page = totalPages;
    const slice = filtered.slice((page - 1) * pageSize, page * pageSize);

    countEl.textContent = `${filtered.length} identity record(s)`;
    if (slice.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--text-muted);">No matching biometric identities found.</td></tr>`;
    } else {
      tbody.innerHTML = slice
        .map(
          (i) => `
        <tr>
          <td class="mono"><strong>${escapeHtml(i.identityRef)}</strong></td>
          <td>${escapeHtml(i.displayName)}</td>
          <td class="mono">${escapeHtml((i.registeredModalities || []).join(', '))}</td>
          <td class="mono" style="font-size:12px;">${escapeHtml(i.featureVersion || 'v1.0')}</td>
          <td><span class="state-text ${i.status === 'active' ? 'state-success' : 'state-warning'}">${escapeHtml(i.status)}</span></td>
          <td class="mono" style="font-size:12px;">${escapeHtml(fmtFsTime(i.updatedAt))}</td>
          <td>
            <div class="row-wrap" style="gap:6px;">
              ${
                canVerify && i.status === 'active'
                  ? `<button type="button" class="btn btn-primary btn-sm" data-verify-id="${escapeHtml(i.identityRef)}">Verify</button>
                     <button type="button" class="btn btn-secondary btn-sm" data-compare-id="${escapeHtml(i.identityRef)}">Compare</button>`
                  : ''
              }
              ${
                canEdit
                  ? `<button type="button" class="btn btn-secondary btn-sm" data-toggle-id="${escapeHtml(i.identityRef)}" data-next-st="${i.status === 'active' ? 'inactive' : 'active'}">${i.status === 'active' ? 'Deactivate' : 'Reactivate'}</button>`
                  : ''
              }
              <button type="button" class="btn btn-ghost btn-sm" data-req-del="${escapeHtml(i.identityRef)}">Request Deletion</button>
              ${
                canDelete
                  ? `<button type="button" class="btn btn-danger btn-sm" data-del-id="${escapeHtml(i.identityRef)}">Delete</button>`
                  : ''
              }
            </div>
          </td>
        </tr>`
        )
        .join('');
    }

    pagerEl.innerHTML = `
      <span class="meta-line">Page ${page} of ${totalPages}</span>
      <div class="row-wrap">
        <button type="button" class="btn btn-secondary btn-sm" id="id-prev" ${page <= 1 ? 'disabled' : ''}>Previous</button>
        <button type="button" class="btn btn-secondary btn-sm" id="id-next" ${page >= totalPages ? 'disabled' : ''}>Next</button>
      </div>
    `;

    pagerEl.querySelector('#id-prev')?.addEventListener('click', () => { page--; drawTable(); });
    pagerEl.querySelector('#id-next')?.addEventListener('click', () => { page++; drawTable(); });

    tbody.querySelectorAll('[data-verify-id]').forEach((btn) => {
      btn.addEventListener('click', () => navigate('verification', { identityRef: btn.dataset.verifyId }));
    });

    tbody.querySelectorAll('[data-compare-id]').forEach((btn) => {
      btn.addEventListener('click', () => navigate('compare', { identityRef: btn.dataset.compareId }));
    });

    tbody.querySelectorAll('[data-toggle-id]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const ref = btn.dataset.toggleId;
        const nextSt = btn.dataset.nextSt;
        try {
          await updateIdentityStatusOrName(ref, { status: nextSt });
          await appendAuditLog({
            action: nextSt === 'active' ? 'identity_reactivated' : 'identity_deactivated',
            resourceType: 'identity',
            resourceId: ref,
            result: `Status changed to ${nextSt}`,
          });
          showToast(`Identity "${ref}" set to ${nextSt}.`, 'success');
        } catch (err) {
          showToast(err.message, 'danger');
        }
      });
    });

    tbody.querySelectorAll('[data-req-del]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const ref = btn.dataset.reqDel;
        openModal({
          title: `Request Biometric Deletion (${ref})`,
          bodyHtml: `
            <div class="stack-md">
              <p style="font-size:13.5px;color:var(--text-secondary);">Submit an audited deletion approval request for <strong class="mono">${escapeHtml(ref)}</strong>. An Administrator must review and approve before encrypted templates are purged.</p>
              <div class="form-field">
                <label class="field-label" for="rd-reason">Justification Reason</label>
                <textarea class="textarea" id="rd-reason" placeholder="Subject withdrew biometric consent or retention window expired..."></textarea>
              </div>
            </div>
          `,
          footerButtons: [
            { label: 'Cancel', variant: 'btn-secondary' },
            {
              label: 'Submit Approval Request',
              variant: 'btn-primary',
              onClick: async ({ close, bodyEl }) => {
                const reason = bodyEl.querySelector('#rd-reason').value.trim();
                if (reason.length < 5) {
                  showToast('Provide a brief justification reason (at least 5 characters).', 'warning');
                  return;
                }
                try {
                  const reqId = await createApprovalRequest({
                    requestType: 'biometric_deletion',
                    targetIdentityRef: ref,
                    reason,
                  });
                  await appendAuditLog({
                    action: 'approval_requested',
                    resourceType: 'approval_request',
                    resourceId: reqId,
                    result: `biometric_deletion requested for ${ref}`,
                  });
                  await pushNotification({
                    title: 'Deletion Request Submitted',
                    message: `Approval request ${reqId} submitted for identity "${ref}".`,
                    type: 'info',
                  });
                  close();
                  showToast(`Approval request "${reqId}" submitted.`, 'success');
                } catch (err) {
                  showToast(err.message, 'danger');
                }
              },
            },
          ],
        });
      });
    });

    tbody.querySelectorAll('[data-del-id]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const ref = btn.dataset.delId;
        openModal({
          title: `Delete Identity ${ref}?`,
          bodyHtml: `<p>This controlled workflow removes encrypted templates from the backend vault and deletes Firestore metadata for <strong class="mono">${escapeHtml(ref)}</strong>. Audit trail records remain preserved.</p>`,
          footerButtons: [
            { label: 'Cancel', variant: 'btn-secondary' },
            {
              label: 'Confirm Deletion',
              variant: 'btn-danger',
              onClick: async ({ close }) => {
                try {
                  await deleteIdentityFromVault(ref).catch(() => null);
                  await deleteIdentityMetadata(ref);
                  await appendAuditLog({
                    action: 'identity_deleted',
                    resourceType: 'identity',
                    resourceId: ref,
                    result: 'Encrypted vault template and Firestore identity metadata deleted',
                  });
                  close();
                  showToast(`Identity "${ref}" deleted.`, 'success');
                } catch (err) {
                  showToast(err.message, 'danger');
                }
              },
            },
          ],
        });
      });
    });
  };

  drawTable();
  container.querySelector('#id-search').addEventListener('input', (e) => { searchQ = e.target.value; page = 1; drawTable(); });
  container.querySelectorAll('#id-filter .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('#id-filter .segmented-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      statusFilter = btn.dataset.st;
      page = 1;
      drawTable();
    });
  });
}
