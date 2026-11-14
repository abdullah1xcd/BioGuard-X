import {
  extractFaceFeatures,
  captureMultiFrameFaceFeatures,
  extractVoiceFeaturesFromPCM,
  extractFingerprintFeatures,
  inspectLiveFaceGuidance,
  ensureFaceEngineReady,
  decodeAudioFileToPCM,
  makeSeededVector,
} from './biometrics.js';
import {
  enrollBiometricIdentity,
  verifyMultimodalBiometrics,
  deleteIdentityFromVault,
  requestLivenessChallenge,
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
  isDevTestingModeActive,
} from './config.js';
import { drawWaveform, drawVerificationTrendChart, observeResponsiveChart } from './charts.js';
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
  openCameraStream,
  createLiveVideoElement,
} from './ui.js';

function fmtFsTime(ts) {
  if (!ts) return '—';
  const d = typeof ts.toDate === 'function' ? ts.toDate() : new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatLivenessBadge(v) {
  const status = v.livenessStatus || (v.livenessPassed === true ? 'LIVENESS PASSED' : v.livenessPassed === false ? 'LIVENESS FAILED' : 'INCONCLUSIVE');
  const cls = status === 'LIVENESS PASSED' ? 'state-success' : status === 'LIVENESS FAILED' ? 'state-danger' : 'state-warning';
  return `<span class="state-text ${cls}">${escapeHtml(status)}</span>`;
}

function formatDecisionBadge(v) {
  const dec = v.finalDecision || (v.outcome === 'match' ? 'VERIFIED' : v.outcome === 'no_match' ? 'REJECTED' : 'INCONCLUSIVE');
  const cls = dec === 'VERIFIED' ? 'state-success' : dec === 'REJECTED' ? 'state-danger' : 'state-warning';
  return `<span class="state-text ${cls}">${escapeHtml(dec)}</span>`;
}

// 1. MAIN DASHBOARD
export function renderOverview(container, { appState, navigate }) {
  const { identities, verifications, alerts, health, permissions } = appState;
  const passCount = verifications.filter((v) => v.finalDecision === 'VERIFIED' || (!v.finalDecision && v.outcome === 'match')).length;
  const failCount = verifications.filter((v) => v.finalDecision === 'REJECTED' || (!v.finalDecision && v.outcome === 'no_match')).length;
  const incCount = verifications.filter((v) => v.finalDecision === 'INCONCLUSIVE' || (!v.finalDecision && v.outcome === 'not_evaluated')).length;
  const evalCount = passCount + failCount;
  const opSuccessRate = evalCount ? ((passCount / evalCount) * 100).toFixed(1) : '—';
  const labeledCount = verifications.filter((v) => v.groundTruth === 'genuine' || v.groundTruth === 'impostor').length;
  const captureFailures = verifications.filter((v) => v.captureFailure === true).length;
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

  const systemOk = health?.status === 'ok' && appState.firestoreOk && health?.vault_ready;
  const fsTel = getFirestoreTelemetry();

  let dashDays = 'all';
  let dashSearch = '';
  let disconnectTrendObs = null;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Dashboard</h1>
        <p class="page-subtitle">Overview of enrolled biometric identities, verification decisions, security risk, and platform health.</p>
      </div>
      <div class="page-actions">
        ${permissions.includes('create_identity') ? `<button class="btn btn-secondary" type="button" data-goto="enrollment">Enroll Identity</button>` : ''}
        ${permissions.includes('perform_verification') ? `<button class="btn btn-primary" type="button" data-goto="verification">Verify Identity</button>` : ''}
      </div>
    </div>

    <div class="kpi-strip">
      <div class="kpi-cell">
        <span class="kpi-label">Enrolled Identities</span>
        <span class="kpi-value">${identities.length}</span>
        <span class="kpi-meta">${identities.filter((i) => i.status === 'active').length} active in encrypted vault</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Verified / Rejected / Inc.</span>
        <span class="kpi-value">${passCount} / ${failCount} / ${incCount}</span>
        <span class="kpi-meta">Operational rate ${opSuccessRate}% · ${labeledCount} labeled · ${captureFailures} capture fail</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Security Risk Score</span>
        <span class="kpi-value">${securityRiskScore} / 100</span>
        <span class="kpi-meta"><span class="${riskCls}">${riskLabel} Risk</span> · ${openAlerts} open alert(s)</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Platform Readiness</span>
        <span class="kpi-value" style="font-size:21px;">${systemOk ? 'Operational' : 'Degraded'}</span>
        <span class="kpi-meta">${avgLatencyMs !== null ? `Avg latency: ${avgLatencyMs} ms` : 'Awaiting verification timing'}</span>
      </div>
    </div>

    ${
      showQuickStart
        ? `
      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Getting Started</h2>
            <p class="panel-subtitle">Enroll a biometric profile, verify identity claims with adaptive fusion, and monitor security analytics</p>
          </div>
        </div>
        <div class="quickstart-grid">
          <div class="quickstart-step">
            <div class="stack-sm" style="gap:4px;">
              <span class="quickstart-num">01. Enroll</span>
              <strong>Register Biometric Profile</strong>
              <p style="font-size:13px;color:var(--text-secondary);">Follow the 5-step guided flow to capture Face, Voice, or Fingerprint samples with automated quality gates.</p>
            </div>
            ${permissions.includes('create_identity') ? `<button type="button" class="btn btn-secondary btn-sm" data-goto="enrollment" style="align-self:flex-start;">Open Enrollment</button>` : '<span class="meta-line">Requires Operator role</span>'}
          </div>
          <div class="quickstart-step">
            <div class="stack-sm" style="gap:4px;">
              <span class="quickstart-num">02. Verify &amp; Search</span>
              <strong>Identity Verification</strong>
              <p style="font-size:13px;color:var(--text-secondary);">Verify 1:1 identity claims with multi-frame liveness screening or search across the encrypted vault (1:N).</p>
            </div>
            ${permissions.includes('perform_verification') ? `<button type="button" class="btn btn-secondary btn-sm" data-goto="verification" style="align-self:flex-start;">Open Verification</button>` : '<span class="meta-line">Requires Operator role</span>'}
          </div>
          <div class="quickstart-step">
            <div class="stack-sm" style="gap:4px;">
              <span class="quickstart-num">03. Monitor</span>
              <strong>Accuracy &amp; Threat Review</strong>
              <p style="font-size:13px;color:var(--text-secondary);">Review measured FAR/FRR/EER metrics across isolated datasets in Analytics &amp; Reports.</p>
            </div>
            <button type="button" class="btn btn-secondary btn-sm" data-goto="analytics" style="align-self:flex-start;">Open Analytics</button>
          </div>
        </div>
      </section>`
        : ''
    }

    <div class="grid-sidebar-split">
      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Recent Verification Activity</h2>
            <p class="panel-subtitle">Filter by date window or search identityRef / reason code</p>
          </div>
          <div class="row-wrap">
            <button class="btn btn-ghost btn-sm" type="button" data-goto="analytics">Analytics</button>
            ${permissions.includes('manage_alerts') ? `<button class="btn btn-ghost btn-sm" type="button" data-goto="threat_intel">Threat Analysis</button>` : ''}
          </div>
        </div>

        <div class="row-between">
          <div class="segmented" id="ov-days">
            <button type="button" class="segmented-btn active" data-days="all">All</button>
            <button type="button" class="segmented-btn" data-days="30">30d</button>
            <button type="button" class="segmented-btn" data-days="7">7d</button>
            <button type="button" class="segmented-btn" data-days="1">Today</button>
          </div>
          <input type="search" class="input responsive-search" id="ov-search" placeholder="Filter identityRef or reason..." style="min-height:36px;" />
        </div>

        <canvas class="chart-canvas" id="ov-trend-canvas" width="480" height="170"></canvas>

        <div id="ov-recent-wrap"></div>
      </section>

      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Platform Status</h2>
            <p class="panel-subtitle">Core security, database, vault encryption, and AI services</p>
          </div>
        </div>
        <div class="divider-list" style="font-size:13.5px;">
          <div class="divider-row">
            <span>Authentication &amp; Role</span>
            <span class="state-text state-success">Signed In (${escapeHtml(appState.profile?.role || 'viewer')})</span>
          </div>
          <div class="divider-row">
            <span>Cloud Firestore Sync</span>
            <span class="state-text ${appState.firestoreOk ? 'state-success' : 'state-danger'}">${appState.firestoreOk ? 'Connected' : 'Offline'}${fsTel.avgLatencyMs ? ` (${fsTel.avgLatencyMs}ms)` : ''}</span>
          </div>
          <div class="divider-row">
            <span>Encrypted Biometric Vault</span>
            <span class="state-text ${health?.vault_ready ? 'state-success' : 'state-warning'}">${health?.vault_ready ? 'AES-256-GCM Active' : 'Not Configured'}</span>
          </div>
          <div class="divider-row">
            <span>AI Security Analyst</span>
            <span class="state-text ${health?.gemini_configured ? 'state-success' : 'state-warning'}">${health?.gemini_configured ? 'Ready' : 'Not Configured'}</span>
          </div>
        </div>

        <details class="advanced-details">
          <summary>Metric Definitions &amp; Model Policy</summary>
          <div class="advanced-details-body" style="font-size:12.5px;color:var(--text-secondary);">
            <div><strong>Model Similarity:</strong> Feature closeness between probe and reference template (0–100%).</div>
            <div><strong>Confidence:</strong> Certainty calibration combining threshold margin, quality, liveness, and cross-modal agreement.</div>
            <div><strong>Classification Accuracy:</strong> Ground-truth genuine vs. impostor separation accuracy (never computed from unlabeled attempts).</div>
            <div><strong>Operational Rate:</strong> Ratio of operational attempts ending in VERIFIED vs. total evaluated.</div>
            <div><strong>Capture Failure Rate:</strong> Submissions blocked pre-match due to blur, poor illumination, or insufficient ridge minutiae.</div>
            <div class="row-between" style="padding-top:6px;border-top:1px solid var(--border-hairline);"><span>Face / Voice / FP</span><span class="mono">FaceRes-1024D · CMVN-96D · RANSAC</span></div>
            <div class="row-between"><span>Active Policy</span><span class="mono">${escapeHtml(appState.settings?.fusionPolicy || 'hierarchical_adaptive')} (F:${appState.settings?.faceThreshold ?? 0.72})</span></div>
          </div>
        </details>
      </section>
    </div>
  `;

  const recentWrap = container.querySelector('#ov-recent-wrap');
  const trendCanvas = container.querySelector('#ov-trend-canvas');

  const drawFilteredDashboard = () => {
    const now = Date.now();
    const term = dashSearch.trim().toLowerCase();
    const filtered = verifications.filter((v) => {
      if (dashDays !== 'all') {
        const ms = typeof v.createdAt?.toMillis === 'function' ? v.createdAt.toMillis() : 0;
        const cutoff = now - Number(dashDays) * 86400_000;
        if (ms < cutoff) return false;
      }
      if (term) {
        return (
          (v.identityRef || '').toLowerCase().includes(term) ||
          (v.reasonCode || '').toLowerCase().includes(term) ||
          (v.finalDecision || '').toLowerCase().includes(term)
        );
      }
      return true;
    });

    if (disconnectTrendObs) disconnectTrendObs();
    disconnectTrendObs = observeResponsiveChart(trendCanvas, (cv) => drawVerificationTrendChart(cv, filtered));

    if (filtered.length === 0) {
      recentWrap.innerHTML = `<div class="empty-state"><div class="empty-title">No matching verification records</div><div class="empty-desc">Adjust your date window or filter, or run a verification check.</div></div>`;
      return;
    }

    recentWrap.innerHTML = `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Identity Ref</th>
              <th>Pipeline</th>
              <th>Decision</th>
              <th>Liveness</th>
              <th>Risk</th>
              <th class="num-col">Similarity</th>
              <th class="num-col">Latency</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            ${filtered
              .slice(0, 8)
              .map((v) => {
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
                  <td>${formatDecisionBadge(v)}</td>
                  <td>${formatLivenessBadge(v)}</td>
                  <td>${riskHtml}</td>
                  <td class="num-col">${fmtPct(v.score || 0)}</td>
                  <td class="num-col">${latHtml}</td>
                  <td class="mono" style="font-size:12px;">${escapeHtml(fmtFsTime(v.createdAt))}</td>
                </tr>`;
              })
              .join('')}
          </tbody>
        </table>
      </div>
    `;
  };

  drawFilteredDashboard();

  container.querySelectorAll('#ov-days .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('#ov-days .segmented-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      dashDays = btn.dataset.days;
      drawFilteredDashboard();
    });
  });

  let searchTimer = null;
  container.querySelector('#ov-search').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      dashSearch = e.target.value;
      drawFilteredDashboard();
    }, 180);
  });

  container.querySelectorAll('[data-goto]').forEach((b) => b.addEventListener('click', () => navigate(b.dataset.goto)));

  return () => {
    clearTimeout(searchTimer);
    if (disconnectTrendObs) disconnectTrendObs();
  };
}

// 2. BIOMETRIC IDENTITY ENROLLMENT (5-Step Guided Flow)
export function renderEnrollment(container, { appState, navigate }) {
  if (!appState.permissions.includes('create_identity')) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Your role (${escapeHtml(appState.profile?.role)}) is not authorized to enroll biometric identities.</div></div></div>`;
    return;
  }

  let currentStep = 1;
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

  const devMode = isDevTestingModeActive(appState);

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Guided Biometric Enrollment</h1>
        <p class="page-subtitle">5-step quality-gated capture across Identity, Face, Voice, Fingerprint, and Final Readiness Review.</p>
      </div>
      ${
        devMode
          ? `<div class="page-actions"><button type="button" class="btn btn-secondary" id="be-fill-all">Fill All QA Test Samples</button></div>`
          : ''
      }
    </div>

    ${
      devMode
        ? `<div class="dev-mode-strip">
            <div><strong>Developer / Testing Mode Active</strong> — Synthetic QA samples are for authorized validation only and are tagged as synthetic probes.</div>
          </div>`
        : ''
    }

    <div class="enroll-stepper" role="tablist" aria-label="Enrollment Steps">
      <button type="button" class="step-pill active" data-step-btn="1"><span class="step-num">1</span>Identity &amp; Consent</button>
      <button type="button" class="step-pill" data-step-btn="2"><span class="step-num">2</span>Face</button>
      <button type="button" class="step-pill" data-step-btn="3"><span class="step-num">3</span>Voice</button>
      <button type="button" class="step-pill" data-step-btn="4"><span class="step-num">4</span>Fingerprint</button>
      <button type="button" class="step-pill" data-step-btn="5"><span class="step-num">5</span>Review &amp; Enroll</button>
    </div>

    <form id="be-form" class="stack-lg">
      <!-- STEP 1 -->
      <section class="panel stack-md" data-step-panel="1">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Step 1 · Subject Details &amp; Explicit Consent</h2>
            <p class="panel-subtitle">Identify the subject and confirm informed biometric storage consent</p>
          </div>
        </div>
        <div class="form-grid">
          <div class="form-field">
            <label class="field-label" for="be-name">Display Name (Required)</label>
            <input class="input" id="be-name" required maxlength="120" placeholder="Amira Al-Mansoor" />
          </div>
          <div class="form-field">
            <label class="field-label" for="be-ref">Identity Reference ID (Required)</label>
            <input class="input mono" id="be-ref" required pattern="^[a-zA-Z0-9_-]{2,64}$" placeholder="amira_al_mansoor" />
          </div>
          <div class="form-field full">
            <label class="checkbox-row">
              <input type="checkbox" id="be-consent" required />
              <span><strong>Explicit Biometric Consent:</strong> I confirm the subject has granted explicit consent to extract and encrypt their biometric templates in the AES-256-GCM vault under operator governance.</span>
            </label>
          </div>
        </div>
        <div class="row-between">
          <span class="meta-line">Next: Capture at least one modality (Face, Voice, or Fingerprint).</span>
          <button type="button" class="btn btn-primary" data-step-next="2">Next: Face Capture &rarr;</button>
        </div>
      </section>

      <!-- STEP 2: FACE -->
      <section class="panel stack-md" data-step-panel="2" hidden>
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Step 2 · Face Biometrics (Recommended Primary)</h2>
            <p class="panel-subtitle">Multi-frame live webcam liveness capture (3 frames) or crisp front-facing upload</p>
          </div>
          <span id="be-face-st" class="state-text state-neutral">Optional / Primary</span>
        </div>
        <div class="preview-frame" id="be-face-prev">No face image</div>
        <p style="font-size:13px;color:var(--text-secondary);">Look directly into the camera in even front lighting. Live capture acquires 3 frames (~220ms apart) and validates motion plus inter-frame identity consistency.</p>
        <div id="be-face-q" class="meta-line">Quality &amp; alignment check runs automatically upon capture or upload.</div>
        <div class="row-wrap">
          <button type="button" class="btn btn-secondary btn-sm" id="be-cam-start">Live Camera</button>
          <button type="button" class="btn btn-primary btn-sm" id="be-cam-snap" disabled>Capture 3 Frames</button>
          <button type="button" class="btn btn-ghost btn-sm" id="be-cam-stop" hidden>Stop</button>
          <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Photo<input type="file" id="be-face-file" accept="image/*" hidden /></label>
          <button type="button" class="btn btn-ghost btn-sm" id="be-face-clear" hidden>Replace / Clear</button>
          ${devMode ? `<button type="button" class="btn btn-ghost btn-sm" id="be-face-sample">QA Sample</button>` : ''}
        </div>
        <div class="row-between" style="padding-top:6px;border-top:1px solid var(--border-hairline);">
          <button type="button" class="btn btn-secondary btn-sm" data-step-prev="1">&larr; Back</button>
          <button type="button" class="btn btn-primary btn-sm" data-step-next="3">Next: Voice &rarr;</button>
        </div>
      </section>

      <!-- STEP 3: VOICE -->
      <section class="panel stack-md" data-step-panel="3" hidden>
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Step 3 · Voice Biometrics (Speaker Recognition)</h2>
            <p class="panel-subtitle">Speaker identity verification (96-D 16kHz CMVN MFCC + Delta + F0) — independent of spoken words</p>
          </div>
          <span id="be-voice-st" class="state-text state-neutral">Optional</span>
        </div>
        <canvas class="waveform-canvas" id="be-voice-wave" width="380" height="86"></canvas>
        <div id="be-voice-audio-slot" hidden><audio id="be-voice-player" controls style="width:100%;height:34px;"></audio></div>
        <p style="font-size:13px;color:var(--text-secondary);">Speak naturally for 2.4+ seconds in a quiet environment (at least 0.8s voiced speech required). Extracts speaker vocal-tract embedding rather than transcribing text.</p>
        <div id="be-voice-q" class="meta-line">Speech duration, SNR, and clipping checks run automatically.</div>
        <div class="row-wrap">
          <button type="button" class="btn btn-secondary btn-sm" id="be-mic-rec">Record Mic (2.4s)</button>
          <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Audio<input type="file" id="be-voice-file" accept="audio/*" hidden /></label>
          <button type="button" class="btn btn-ghost btn-sm" id="be-voice-clear" hidden>Replace / Clear</button>
          ${devMode ? `<button type="button" class="btn btn-ghost btn-sm" id="be-voice-sample">QA Sample</button>` : ''}
        </div>
        <div class="row-between" style="padding-top:6px;border-top:1px solid var(--border-hairline);">
          <button type="button" class="btn btn-secondary btn-sm" data-step-prev="2">&larr; Back</button>
          <button type="button" class="btn btn-primary btn-sm" data-step-next="4">Next: Fingerprint &rarr;</button>
        </div>
      </section>

      <!-- STEP 4: FINGERPRINT -->
      <section class="panel stack-md" data-step-panel="4" hidden>
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Step 4 · Fingerprint Recognition</h2>
            <p class="panel-subtitle">Adaptive Gabor ridge enhancement, Zhang-Suen skeletonization, and minutiae descriptor extraction</p>
          </div>
          <span id="be-fp-st" class="state-text state-neutral">Optional</span>
        </div>
        <div class="notice-strip">
          <div>
            <strong>Hardware Sensor &amp; PAD Limitation</strong>
            <div>Browsers cannot access built-in laptop/phone fingerprint hardware without native vendor bridges. Upload an optical/capacitive fingerprint ridge image (&ge;96&times;96px). Image uploads have no hardware PAD sensor (Liveness: NOT SUPPORTED).</div>
          </div>
        </div>
        <div class="preview-frame fingerprint-frame" id="be-fp-prev" style="margin:0 auto;">No print image</div>
        <div id="be-fp-q" class="meta-line">Sharpness, ridge wavelength (px), orientation coherence, and minutiae validation run automatically.</div>
        <div class="row-wrap">
          <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Print Image<input type="file" id="be-fp-file" accept="image/*" hidden /></label>
          <button type="button" class="btn btn-ghost btn-sm" id="be-fp-clear" hidden>Replace / Clear</button>
          ${devMode ? `<button type="button" class="btn btn-ghost btn-sm" id="be-fp-sample">QA Sample</button>` : ''}
        </div>
        <div class="row-between" style="padding-top:6px;border-top:1px solid var(--border-hairline);">
          <button type="button" class="btn btn-secondary btn-sm" data-step-prev="3">&larr; Back</button>
          <button type="button" class="btn btn-primary btn-sm" data-step-next="5">Next: Review &amp; Enroll &rarr;</button>
        </div>
      </section>

      <!-- STEP 5: FINAL REVIEW & ENROLL -->
      <section class="panel stack-md" data-step-panel="5" hidden>
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Step 5 · Final Readiness &amp; Quality Review</h2>
            <p class="panel-subtitle">Confirm template readiness before encrypting into the AES-256-GCM vault</p>
          </div>
        </div>
        <div id="be-review-table"></div>
        <div id="be-summary" class="meta-line">Capture or upload at least one biometric modality to enroll.</div>
        <div class="row-between" style="padding-top:6px;border-top:1px solid var(--border-hairline);">
          <button type="button" class="btn btn-secondary btn-sm" data-step-prev="4">&larr; Back</button>
          <button type="submit" class="btn btn-primary" id="be-submit">Enroll Identity</button>
        </div>
      </section>
    </form>

    <div id="be-result"></div>
  `;

  const nameInput = container.querySelector('#be-name');
  const refInput = container.querySelector('#be-ref');
  const consentInput = container.querySelector('#be-consent');
  const summaryEl = container.querySelector('#be-summary');
  const reviewTableEl = container.querySelector('#be-review-table');
  const facePrev = container.querySelector('#be-face-prev');
  const faceSt = container.querySelector('#be-face-st');
  const faceQEl = container.querySelector('#be-face-q');
  const camSnap = container.querySelector('#be-cam-snap');
  const camStopBtn = container.querySelector('#be-cam-stop');
  const faceClearBtn = container.querySelector('#be-face-clear');
  const voiceWave = container.querySelector('#be-voice-wave');
  const voiceSt = container.querySelector('#be-voice-st');
  const voiceQEl = container.querySelector('#be-voice-q');
  const voiceAudioSlot = container.querySelector('#be-voice-audio-slot');
  const voicePlayer = container.querySelector('#be-voice-player');
  const voiceClearBtn = container.querySelector('#be-voice-clear');
  const fpPrev = container.querySelector('#be-fp-prev');
  const fpSt = container.querySelector('#be-fp-st');
  const fpQEl = container.querySelector('#be-fp-q');
  const fpClearBtn = container.querySelector('#be-fp-clear');

  const haltCameraUI = () => {
    stopCamera();
    camSnap.disabled = true;
    camStopBtn.hidden = true;
  };

  const renderReviewTable = () => {
    const modStatus = (hasVec, qScore, goodThresh, detail) => {
      if (!hasVec) return { badge: 'NOT PROVIDED', cls: 'state-neutral', detail: 'Not captured' };
      if ((qScore ?? 0) >= goodThresh) return { badge: 'READY', cls: 'state-success', detail };
      return { badge: 'NEEDS IMPROVEMENT', cls: 'state-warning', detail };
    };
    const fRow = modStatus(Boolean(faceVec), faceQuality?.faceQualityScore, 60, faceQuality ? `Q:${faceQuality.faceQualityScore}/100 · ${faceQuality.feedbackLabel || 'Extracted'}${faceQuality.multiFrameVerified ? ' · 3-Frame Live' : ''}` : '');
    const vRow = modStatus(Boolean(voiceVec), voiceQuality?.voiceQualityScore, 55, voiceQuality ? `Q:${voiceQuality.voiceQualityScore}/100 · ${voiceQuality.feedbackLabel || ''} · ${voiceQuality.durationSec}s` : '');
    const fpRow = modStatus(Boolean(fpTemplate), fpQuality?.qualityScore, 55, fpQuality ? `${fpQuality.qualityLabel || ''} · ${fpQuality.minutiaeHeuristicCount} minutiae · ${fpQuality.templateStatus || ''}` : '');

    reviewTableEl.innerHTML = `
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Modality</th><th>Readiness</th><th>Quality &amp; Diagnostics</th><th>Edit</th></tr></thead>
          <tbody>
            <tr>
              <td><strong>Face</strong></td>
              <td><span class="state-text ${fRow.cls}">${fRow.badge}</span></td>
              <td class="mono" style="font-size:12px;">${escapeHtml(fRow.detail)}</td>
              <td><button type="button" class="btn btn-ghost btn-sm" data-jump-step="2">${faceVec ? 'Replace' : 'Capture'}</button></td>
            </tr>
            <tr>
              <td><strong>Voice</strong></td>
              <td><span class="state-text ${vRow.cls}">${vRow.badge}</span></td>
              <td class="mono" style="font-size:12px;">${escapeHtml(vRow.detail)}</td>
              <td><button type="button" class="btn btn-ghost btn-sm" data-jump-step="3">${voiceVec ? 'Replace' : 'Capture'}</button></td>
            </tr>
            <tr>
              <td><strong>Fingerprint</strong></td>
              <td><span class="state-text ${fpRow.cls}">${fpRow.badge}</span></td>
              <td class="mono" style="font-size:12px;">${escapeHtml(fpRow.detail)}</td>
              <td><button type="button" class="btn btn-ghost btn-sm" data-jump-step="4">${fpTemplate ? 'Replace' : 'Upload'}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    `;
    reviewTableEl.querySelectorAll('[data-jump-step]').forEach((b) => {
      b.addEventListener('click', () => goToStep(Number(b.dataset.jumpStep)));
    });
  };

  const updateSummary = () => {
    const ready = [];
    if (faceVec) ready.push(`Face (Q:${faceQuality?.faceQualityScore ?? '—'}/100)`);
    if (voiceVec) ready.push(`Voice (Q:${voiceQuality?.voiceQualityScore ?? '—'}/100)`);
    if (fpTemplate) ready.push(`Fingerprint (${fpQuality?.qualityLabel || 'Q:' + (fpQuality?.qualityScore ?? '—')})`);
    const consentStatus = consentInput.checked ? 'Consent confirmed' : 'Consent required';
    summaryEl.textContent = ready.length
      ? `${ready.join(' · ')} — ${consentStatus}`
      : `Add at least one biometric modality in Steps 2–4 (${consentStatus}).`;
    renderReviewTable();
  };

  const goToStep = (stepNum) => {
    currentStep = Math.max(1, Math.min(5, stepNum));
    if (currentStep !== 2) haltCameraUI();
    container.querySelectorAll('[data-step-panel]').forEach((p) => {
      p.hidden = Number(p.dataset.stepPanel) !== currentStep;
    });
    container.querySelectorAll('[data-step-btn]').forEach((b) => {
      const n = Number(b.dataset.stepBtn);
      b.classList.toggle('active', n === currentStep);
      const done =
        (n === 1 && Boolean(nameInput.value.trim() && refInput.value.trim() && consentInput.checked)) ||
        (n === 2 && Boolean(faceVec)) ||
        (n === 3 && Boolean(voiceVec)) ||
        (n === 4 && Boolean(fpTemplate));
      b.classList.toggle('completed', done && n !== currentStep);
    });
    if (currentStep === 5) updateSummary();
  };

  container.querySelectorAll('[data-step-btn]').forEach((b) => {
    b.addEventListener('click', () => goToStep(Number(b.dataset.stepBtn)));
  });
  container.querySelectorAll('[data-step-next]').forEach((b) => {
    b.addEventListener('click', () => goToStep(Number(b.dataset.stepNext)));
  });
  container.querySelectorAll('[data-step-prev]').forEach((b) => {
    b.addEventListener('click', () => goToStep(Number(b.dataset.stepPrev)));
  });

  consentInput.addEventListener('change', updateSummary);
  refInput.addEventListener('input', () => {
    refEditedManually = refInput.value.trim().length > 0;
  });
  nameInput.addEventListener('input', () => {
    if (!refEditedManually) {
      refInput.value = slugifyIdentityRef(nameInput.value);
    }
  });

  const applyFaceExtraction = (res, sourceCanvasOrImg, label) => {
    faceVec = res.vector;
    faceQuality = res.quality;
    facePrev.innerHTML = '';
    const c = document.createElement('canvas');
    c.width = 240; c.height = 180;
    c.getContext('2d').drawImage(sourceCanvasOrImg, 0, 0, 240, 180);
    facePrev.appendChild(c);

    faceSt.className = `state-text ${faceQuality.spoofRiskFlag ? 'state-warning' : 'state-success'}`;
    faceSt.textContent = faceQuality.spoofRiskFlag ? 'Spoof Warning' : faceQuality.feedbackLabel || label;
    faceQEl.textContent = `Quality: ${faceQuality.faceQualityScore}/100 · Yaw ${faceQuality.poseYawDeg}° · Sharpness ${faceQuality.sharpness}${
      typeof faceQuality.antispoofScore === 'number' ? ` · AntiSpoof ${Math.round(faceQuality.antispoofScore * 100)}%` : ''
    }${faceQuality.multiFrameVerified ? ` · 3-Frame Cons=${faceQuality.frameConsistencyCosine}` : ''}`;
    faceClearBtn.hidden = false;
    updateSummary();
  };

  const setFaceReal = async (source, label = 'Face Quality Good', extraQuality = {}) => {
    faceSt.className = 'state-text state-warning';
    faceSt.textContent = 'Analyzing...';
    faceQEl.textContent = 'Checking face alignment, lighting quality, and anti-spoofing...';
    try {
      const res = await extractFaceFeatures(source, extraQuality);
      applyFaceExtraction(res, source, label);
    } catch (err) {
      faceVec = null;
      faceQuality = null;
      faceClearBtn.hidden = true;
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = err.feedbackLabel || 'Rejected';
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
      feedbackLabel: 'QA Sample',
      captureSource: 'test_sample',
      model: 'synthetic-qa-1024d',
    };
    faceSt.className = 'state-text state-neutral';
    faceSt.textContent = 'QA Sample';
    faceQEl.textContent = 'Synthetic deterministic QA probe (non-camera)';
    faceClearBtn.hidden = false;
    updateSummary();
  };

  const setVoice = (samples, rate, label = 'Ready', captureSource = 'upload', wavUrl = null) => {
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
      voiceSt.textContent = voiceQuality.feedbackLabel || (spoofCount ? 'Quality Warning' : label);
      voiceQEl.textContent = `${voiceQuality.feedbackLabel || 'Voice Quality Good'} · Q:${voiceQuality.voiceQualityScore}/100 · ${voiceQuality.durationSec}s speech · SNR ${voiceQuality.snrEstimateDb}dB`;
      voiceClearBtn.hidden = false;
      updateSummary();
    } catch (err) {
      voiceVec = null;
      voiceQuality = null;
      voiceClearBtn.hidden = true;
      voiceSt.className = 'state-text state-danger';
      voiceSt.textContent = 'Rejected';
      voiceQEl.textContent = err.message;
      updateSummary();
      showToast(err.message, 'danger');
    }
  };

  const setFp = (source, label = 'Good Quality', captureSource = 'upload') => {
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
      fpSt.textContent = captureSource === 'test_sample' ? 'QA Sample' : fpQuality.qualityLabel || label;
      fpQEl.textContent = `${fpQuality.qualityLabel || 'Good Quality'} · Q:${fpQuality.qualityScore}/100 · ${fpQuality.minutiaeHeuristicCount} minutiae · Coherence ${fpQuality.meanCoherence} · Wavelength ${fpQuality.meanWavelengthPx ?? '—'}px · ${fpQuality.templateStatus || ''}`;
      fpClearBtn.hidden = false;
      updateSummary();
    } catch (err) {
      fpTemplate = null;
      fpQuality = null;
      fpClearBtn.hidden = true;
      fpSt.className = 'state-text state-danger';
      fpSt.textContent = err.qualityLabel || 'Rejected';
      fpQEl.textContent = err.message;
      updateSummary();
      showToast(err.message, 'danger');
    }
  };

  faceClearBtn.addEventListener('click', () => {
    haltCameraUI();
    faceVec = null; faceQuality = null;
    facePrev.textContent = 'No face image';
    faceSt.className = 'state-text state-neutral';
    faceSt.textContent = 'Optional / Primary';
    faceQEl.textContent = 'Face sample cleared.';
    faceClearBtn.hidden = true;
    updateSummary();
  });

  voiceClearBtn.addEventListener('click', () => {
    voiceVec = null; voiceQuality = null;
    voiceAudioSlot.hidden = true;
    voiceSt.className = 'state-text state-neutral';
    voiceSt.textContent = 'Optional';
    voiceQEl.textContent = 'Voice sample cleared.';
    voiceClearBtn.hidden = true;
    updateSummary();
  });

  fpClearBtn.addEventListener('click', () => {
    fpTemplate = null; fpQuality = null;
    fpPrev.textContent = 'No print image';
    fpSt.className = 'state-text state-neutral';
    fpSt.textContent = 'Optional';
    fpQEl.textContent = 'Fingerprint sample cleared.';
    fpClearBtn.hidden = true;
    updateSummary();
  });

  container.querySelector('#be-fill-all')?.addEventListener('click', () => {
    haltCameraUI();
    if (!nameInput.value.trim()) nameInput.value = 'Demo Subject';
    if (!refInput.value.trim()) {
      refInput.value = slugifyIdentityRef(nameInput.value) || `subject_${Date.now().toString().slice(-4)}`;
    }
    const seed = refInput.value.trim();
    setFaceSyntheticSample(seed);
    const p = synthesizeSampleVoicePCM(seed, 3);
    setVoice(p.samples, p.sampleRate, 'QA Sample', 'test_sample');
    setFp(renderSampleFingerprintCanvas(seed), 'QA Sample', 'test_sample');
    consentInput.checked = true;
    updateSummary();
    goToStep(5);
    showToast('Loaded synthetic QA test samples across all 3 modalities.', 'neutral');
  });

  container.querySelector('#be-cam-start').addEventListener('click', async () => {
    try {
      haltCameraUI();
      faceSt.className = 'state-text state-warning';
      faceSt.textContent = 'Starting Camera...';
      faceQEl.textContent = 'Initializing face detection models...';
      await ensureFaceEngineReady();

      activeStream = await openCameraStream();
      const wrap = document.createElement('div');
      wrap.className = 'face-guide-wrap';
      const v = await createLiveVideoElement(activeStream);
      const oval = document.createElement('div');
      oval.className = 'face-guide-oval';
      const msgBadge = document.createElement('div');
      msgBadge.className = 'face-guide-status';
      msgBadge.textContent = 'Center face inside oval guide...';

      wrap.appendChild(v);
      wrap.appendChild(oval);
      wrap.appendChild(msgBadge);
      facePrev.innerHTML = '';
      facePrev.appendChild(wrap);
      faceSt.className = 'state-text state-neutral';
      faceSt.textContent = 'Live Preview';
      camSnap.disabled = false;
      camStopBtn.hidden = false;

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
        camSnap.textContent = 'Capturing 3 Frames...';
        faceSt.className = 'state-text state-warning';
        faceSt.textContent = 'Checking 3-Frame Liveness...';
        try {
          const res = await captureMultiFrameFaceFeatures(v, 220);
          haltCameraUI();
          applyFaceExtraction(res, res.canvas, 'Live Capture Verified');
        } catch (err) {
          faceVec = null;
          faceQuality = null;
          faceSt.className = 'state-text state-danger';
          faceSt.textContent = err.feedbackLabel || 'Rejected';
          faceQEl.textContent = err.message;
          showToast(err.message, 'danger');
        } finally {
          camSnap.textContent = 'Capture 3 Frames';
          haltCameraUI();
        }
      };
    } catch (err) {
      haltCameraUI();
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = 'Camera Error';
      showToast(`Camera error: ${err.message}`, 'warning');
    }
  });

  camStopBtn.addEventListener('click', () => {
    haltCameraUI();
    facePrev.textContent = 'No face image';
    faceSt.className = 'state-text state-neutral';
    faceSt.textContent = 'Optional / Primary';
    faceQEl.textContent = 'Camera stopped';
  });

  container.querySelector('#be-face-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 8 * 1024 * 1024) { showToast('Face image exceeds 8 MB limit.', 'danger'); return; }
    try {
      haltCameraUI();
      await setFaceReal(await loadImageFile(f), 'Uploaded ✓', { captureSource: 'upload' });
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });

  container.querySelector('#be-face-sample')?.addEventListener('click', () => {
    haltCameraUI();
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
      setVoice(p.samples, p.sampleRate, 'Recorded ✓', 'microphone', p.wavUrl);
    } catch (err) {
      showToast(`Mic error: ${err.message}`, 'warning');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Record Mic (2.4s)';
    }
  });

  container.querySelector('#be-voice-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const p = await decodeAudioFileToPCM(f);
      setVoice(p.samples, p.sampleRate, 'Uploaded ✓', 'upload');
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });

  container.querySelector('#be-voice-sample')?.addEventListener('click', () => {
    const ref = refInput.value.trim() || 'sample_id';
    const p = synthesizeSampleVoicePCM(ref, 3);
    setVoice(p.samples, p.sampleRate, 'QA Sample', 'test_sample');
  });

  container.querySelector('#be-fp-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try { setFp(await loadImageFile(f), 'Good Quality', 'upload'); }
    catch (err) { showToast(err.message, 'danger'); }
  });

  container.querySelector('#be-fp-sample')?.addEventListener('click', () => {
    const ref = refInput.value.trim() || 'sample_id';
    setFp(renderSampleFingerprintCanvas(ref), 'QA Sample', 'test_sample');
  });

  container.querySelector('#be-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const identityRef = refInput.value.trim();
    const displayName = nameInput.value.trim();
    const consentRecorded = consentInput.checked;
    const submitBtn = container.querySelector('#be-submit');

    if (!displayName || !identityRef || !/^[a-zA-Z0-9_-]{2,64}$/.test(identityRef)) {
      goToStep(1);
      showToast('Provide a valid Display Name and Reference ID in Step 1.', 'warning');
      return;
    }

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
      showToast('Provide at least one biometric modality before enrolling.', 'warning');
      return;
    }
    if (!consentRecorded) {
      goToStep(1);
      showToast('Explicit biometric consent must be checked before enrollment.', 'warning');
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
      }).catch(() => null);
      await pushNotification({
        title: 'Identity Enrolled',
        message: `${displayName} (${identityRef}) enrolled with [${apiRes.registeredModalities.join(', ')}].`,
        type: 'success',
      }).catch(() => null);

      const usedSynthetic =
        faceQuality?.captureSource === 'test_sample' ||
        voiceQuality?.captureSource === 'test_sample' ||
        fpQuality?.captureSource === 'test_sample';

      const warnHtml = (apiRes.qualityWarnings || []).length
        ? `<div style="font-size:12.5px;color:var(--status-warning);">Quality notes: ${escapeHtml(apiRes.qualityWarnings.join(' · '))}</div>`
        : '';

      const resContainer = container.querySelector('#be-result');
      resContainer.innerHTML = `
        <section class="panel stack-md" style="border-color:rgba(20, 184, 166, 0.4);">
          <div class="row-between">
            <div class="stack-sm" style="gap:2px;">
              <span class="state-text state-success">${fpTemplate ? 'Fingerprint &amp; Biometric Profile Successfully Enrolled' : 'Enrollment Complete'}</span>
              <h3 class="panel-title">${escapeHtml(displayName)} (<span class="mono">${escapeHtml(apiRes.identityRef)}</span>)</h3>
            </div>
            <div class="row-wrap">
              <button type="button" class="btn btn-primary btn-sm" id="be-verify-now">Verify This Identity</button>
              <button type="button" class="btn btn-secondary btn-sm" id="be-view-list">View Identities</button>
            </div>
          </div>

          <div class="divider-list" style="font-size:13.5px;">
            <div class="divider-row">
              <span>Enrolled Modalities</span>
              <span class="mono" style="text-transform:capitalize;">${escapeHtml(apiRes.registeredModalities.join(', '))}</span>
            </div>
            <div class="divider-row">
              <span>Vault Storage &amp; Consent</span>
              <span class="state-text state-success">AES-256-GCM Encrypted · Explicit Consent Recorded</span>
            </div>
            <div class="divider-row">
              <span>Pre-Submission Quality</span>
              <span class="mono">Validated (${apiRes.processingTimeMs} ms)</span>
            </div>
          </div>
          ${usedSynthetic ? `<div class="notice-strip warning"><div><strong>Developer QA Sample Notice</strong><div>This enrollment includes synthetic QA test data and should not be treated as a real subject biometric record.</div></div></div>` : ''}
          ${warnHtml}
        </section>
      `;
      resContainer.querySelector('#be-verify-now')?.addEventListener('click', () => {
        navigate('verification', { identityRef: apiRes.identityRef });
      });
      resContainer.querySelector('#be-view-list')?.addEventListener('click', () => {
        navigate('identities');
      });
      showToast(`Identity "${identityRef}" enrolled.`, 'success');
      haltCameraUI();
    } catch (err) {
      const code = String(err?.code || '');
      const status = Number(err?.status || 0);
      const heading =
        code === 'vault_secret_not_configured'
          ? 'Vault Encryption Secret Not Configured'
          : code.startsWith('firestore_')
          ? 'Firestore Configuration / Permission Error'
          : status >= 500 || code === 'backend_unavailable'
          ? 'Backend / Storage Request Failed'
          : code === 'vault_decryption_failed'
          ? 'Existing Vault Record Decryption Mismatch'
          : 'Enrollment Quality / Validation Rejected';
      container.querySelector('#be-result').innerHTML = `<div class="notice-strip danger"><div><strong>${escapeHtml(heading)}</strong><div>${escapeHtml(err.message)}</div></div></div>`;
      showToast(err.message, 'danger');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Enroll Identity';
    }
  });

  updateSummary();

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
  let activeChallenge = null;

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
  const devMode = isDevTestingModeActive(appState);

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Verification</h1>
        <p class="page-subtitle">Verify an identity claim using live capture or uploaded biometric probes with liveness and risk screening.</p>
      </div>
      ${
        identities.length === 0 && appState.permissions.includes('create_identity')
          ? `<div class="page-actions"><button type="button" class="btn btn-primary" id="mv-go-enroll">Enroll First Identity</button></div>`
          : ''
      }
    </div>

    ${
      devMode
        ? `<div class="dev-mode-strip">
            <div><strong>Developer / Testing Mode Active</strong> — Synthetic QA probe loaders are enabled below (tagged <span class="mono">isTestProbe=true</span>).</div>
            ${
              identities.length > 0
                ? `<div class="row-wrap">
                    <button type="button" class="btn btn-secondary btn-sm" id="mv-load-match">Load Matching QA Probes</button>
                    <button type="button" class="btn btn-ghost btn-sm" id="mv-load-impostor">Load Impostor QA Probes</button>
                  </div>`
                : ''
            }
          </div>`
        : ''
    }

    ${
      identities.length === 0
        ? `<section class="panel"><div class="empty-state"><div class="empty-title">No active identities enrolled yet</div><div class="empty-desc">Enroll at least one biometric identity before running verification checks.</div></div></section>`
        : `
      <div class="panel stack-md">
        <div class="form-grid">
          <div class="form-field">
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

          <div class="form-field" style="justify-content:flex-end;">
            <span class="field-label">Active Evaluation Mode</span>
            <div id="mv-active-summary" class="meta-line" style="min-height:40px;align-items:center;"></div>
          </div>
        </div>

        <details class="advanced-details" id="mv-options-details">
          <summary>Advanced Options (Pipeline, Fusion Policy &amp; Evaluation Label)</summary>
          <div class="advanced-details-body">
            <div class="form-grid">
              <div class="form-field">
                <label class="field-label" for="mv-policy">Fusion Policy</label>
                <select class="select" id="mv-policy">
                  ${FUSION_POLICIES.map((fp) => `<option value="${fp.id}" ${fp.id === defaultPolicy ? 'selected' : ''}>${escapeHtml(fp.label)}</option>`).join('')}
                </select>
                <span id="mv-policy-desc" class="meta-line"></span>
              </div>

              <div class="form-field">
                <label class="field-label" for="mv-gt">Evaluation Trial Label</label>
                <select class="select" id="mv-gt">
                  <option value="unlabeled">Unlabeled (Operational)</option>
                  <option value="genuine">Genuine Trial (Known Same Subject)</option>
                  <option value="impostor">Impostor Trial (Known Different Subject)</option>
                </select>
                <span class="meta-line">Labeled trials feed FAR, FRR, and EER accuracy reports</span>
              </div>
            </div>

            <div class="stack-sm" style="gap:6px;">
              <span class="field-label">Verification Pipeline</span>
              <div class="segmented" id="mv-tabs">
                ${PIPELINE_CATALOG.map((p) => `<button type="button" class="segmented-btn" data-pipe="${p.key}">${escapeHtml(p.label)}</button>`).join('')}
              </div>
              <span id="mv-pipe-desc" class="meta-line"></span>
            </div>

            <label class="checkbox-row">
              <input type="checkbox" id="mv-adaptive" checked />
              <span>Adaptive Risk Enforcement (tighten threshold or require MFA when risk score &ge; 50)</span>
            </label>
          </div>
        </details>

        <div class="grid-3">
          <div class="probe-card" id="mv-card-face">
            <div class="row-between">
              <div>
                <strong>Face Probe</strong>
                <div id="mv-face-req" class="meta-line"></div>
              </div>
              <span id="mv-face-st" class="state-text state-neutral">Empty</span>
            </div>
            <div id="mv-face-challenge-banner" class="challenge-banner" hidden></div>
            <div id="mv-face-live-wrap" class="preview-frame" style="max-height:175px;" hidden></div>
            <div id="mv-face-q" class="meta-line">Live camera or photo upload</div>
            <div class="row-wrap">
              <button type="button" class="btn btn-secondary btn-sm" id="mv-face-cam">Live Camera</button>
              <button type="button" class="btn btn-primary btn-sm" id="mv-face-snap" hidden>Capture</button>
              <button type="button" class="btn btn-ghost btn-sm" id="mv-face-stop" hidden>Stop</button>
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload<input type="file" id="mv-face-file" accept="image/*" hidden /></label>
              ${
                devMode
                  ? `<button type="button" class="btn btn-ghost btn-sm" id="mv-face-gen">Match QA</button>
                     <button type="button" class="btn btn-ghost btn-sm" id="mv-face-imp">Impostor QA</button>`
                  : ''
              }
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
            <div id="mv-voice-challenge-banner" class="challenge-banner" hidden></div>
            <div id="mv-voice-audio-slot" hidden><audio id="mv-voice-player" controls style="width:100%;height:34px;"></audio></div>
            <div id="mv-voice-q" class="meta-line">Record 2.4s microphone or audio upload</div>
            <div class="row-wrap">
              <button type="button" class="btn btn-secondary btn-sm" id="mv-voice-mic">Mic (2.4s)</button>
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload<input type="file" id="mv-voice-file" accept="audio/*" hidden /></label>
              ${
                devMode
                  ? `<button type="button" class="btn btn-ghost btn-sm" id="mv-voice-gen">Match QA</button>
                     <button type="button" class="btn btn-ghost btn-sm" id="mv-voice-imp">Impostor QA</button>`
                  : ''
              }
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
            <div id="mv-fp-q" class="meta-line">Upload ridge scan (&ge;96&times;96px). No browser hardware PAD sensor.</div>
            <div class="row-wrap">
              <label class="btn btn-secondary btn-sm" style="cursor:pointer;">Upload Print<input type="file" id="mv-fp-file" accept="image/*" hidden /></label>
              ${
                devMode
                  ? `<button type="button" class="btn btn-ghost btn-sm" id="mv-fp-gen">Match QA</button>
                     <button type="button" class="btn btn-ghost btn-sm" id="mv-fp-imp">Impostor QA</button>`
                  : ''
              }
            </div>
          </div>
        </div>

        <div class="row-between">
          <span class="meta-line">Matched securely server-side against encrypted AES-256-GCM vault templates.</span>
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
  const activeSummaryEl = container.querySelector('#mv-active-summary');
  const gtSel = container.querySelector('#mv-gt');
  const enrolledInfoEl = container.querySelector('#mv-enrolled-info');
  const pipeDescEl = container.querySelector('#mv-pipe-desc');
  const faceSt = container.querySelector('#mv-face-st');
  const faceQEl = container.querySelector('#mv-face-q');
  const faceLiveWrap = container.querySelector('#mv-face-live-wrap');
  const faceChallengeBanner = container.querySelector('#mv-face-challenge-banner');
  const voiceChallengeBanner = container.querySelector('#mv-voice-challenge-banner');
  const faceSnapBtn = container.querySelector('#mv-face-snap');
  const faceStopBtn = container.querySelector('#mv-face-stop');
  const voiceSt = container.querySelector('#mv-voice-st');
  const voiceQEl = container.querySelector('#mv-voice-q');
  const voiceAudioSlot = container.querySelector('#mv-voice-audio-slot');
  const voicePlayer = container.querySelector('#mv-voice-player');
  const fpSt = container.querySelector('#mv-fp-st');
  const fpQEl = container.querySelector('#mv-fp-q');

  const getSelectedIdentity = () => identities.find((i) => i.identityRef === idSel.value) || identities[0];

  const syncActiveSummary = () => {
    const activePipe = PIPELINE_CATALOG.find((p) => p.key === selectedPipeline) || PIPELINE_CATALOG[0];
    const activePol = FUSION_POLICIES.find((p) => p.id === policySel.value);
    if (activeSummaryEl) {
      activeSummaryEl.textContent = `${activePipe.label} · ${activePol?.label || policySel.value}`;
    }
  };

  const syncPolicyDesc = () => {
    const def = FUSION_POLICIES.find((p) => p.id === policySel.value);
    if (policyDescEl && def) policyDescEl.textContent = def.summary;
    syncActiveSummary();
  };
  syncPolicyDesc();
  policySel.addEventListener('change', syncPolicyDesc);

  const syncAdaptiveUI = () => {
    const idObj = getSelectedIdentity();
    const enrolled = new Set(idObj?.registeredModalities || []);
    enrolledInfoEl.textContent = `Enrolled: ${[...enrolled].join(', ') || 'none'}`;

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
    syncActiveSummary();

    const updateCard = (mod, cardSel, reqSel) => {
      const card = container.querySelector(cardSel);
      const req = container.querySelector(reqSel);
      const isReq = activeDef.requires.includes(mod);
      const isOpt = activeDef.optional.includes(mod) && enrolled.has(mod);
      card.classList.toggle('required-active', isReq);
      card.classList.toggle('inactive', !isReq && !isOpt);
      req.textContent = isReq ? 'Required' : isOpt ? 'Optional secondary' : 'Not used in pipeline';
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
      const spoofCount = (voiceQuality.spoofSignals || []).length;
      voiceSt.className = `state-text ${spoofCount ? 'state-warning' : 'state-success'}`;
      voiceSt.textContent = voiceQuality.feedbackLabel || statusText;
      voiceQEl.textContent = `${voiceQuality.feedbackLabel || 'Voice Ready'} · ${voiceQuality.durationSec}s · Q:${voiceQuality.voiceQualityScore}/100 · SNR:${voiceQuality.snrEstimateDb}dB`;
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
      fpSt.textContent = captureSource === 'test_sample' ? statusText : fpQuality.qualityLabel || statusText;
      fpQEl.textContent = `${fpQuality.qualityLabel || 'Good Quality'} · Minutiae:${fpQuality.minutiaeHeuristicCount} · Coherence:${fpQuality.meanCoherence} · Q:${fpQuality.qualityScore}/100`;
    } catch (err) {
      fpTemplate = null;
      fpQuality = null;
      fpSt.className = 'state-text state-danger';
      fpSt.textContent = err.qualityLabel || 'Rejected';
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

  container.querySelector('#mv-load-match')?.addEventListener('click', () => {
    const idObj = getSelectedIdentity();
    const enrolled = new Set(idObj?.registeredModalities || []);
    const def = PIPELINE_CATALOG.find((p) => p.key === selectedPipeline) || PIPELINE_CATALOG[0];
    const needed = new Set([...def.requires, ...def.optional.filter((m) => enrolled.has(m))]);
    if (needed.has('face')) loadFaceMatch();
    if (needed.has('voice')) loadVoiceMatch();
    if (needed.has('fingerprint')) loadFpMatch();
    showToast('Loaded matching QA probes (labeled Genuine Trial).', 'neutral');
  });

  container.querySelector('#mv-load-impostor')?.addEventListener('click', () => {
    const idObj = getSelectedIdentity();
    const enrolled = new Set(idObj?.registeredModalities || []);
    const def = PIPELINE_CATALOG.find((p) => p.key === selectedPipeline) || PIPELINE_CATALOG[0];
    const needed = new Set([...def.requires, ...def.optional.filter((m) => enrolled.has(m))]);
    if (needed.has('face')) loadFaceImpostor();
    if (needed.has('voice')) loadVoiceImpostor();
    if (needed.has('fingerprint')) loadFpImpostor();
    showToast('Loaded impostor QA probes (labeled Impostor Trial).', 'warning');
  });

  const haltProbeCamera = () => {
    stopCamera();
    faceSnapBtn.hidden = true;
    faceStopBtn.hidden = true;
    faceLiveWrap.hidden = true;
  };

  const describeFaceChallenge = (ch) => {
    if (ch === 'blink') return 'Active Challenge: Blink naturally once during capture';
    if (ch === 'turn_left') return 'Active Challenge: Turn head gently left, then look straight';
    if (ch === 'turn_right') return 'Active Challenge: Turn head gently right, then look straight';
    return 'Hold steady for 3-frame multi-frame liveness check';
  };

  container.querySelector('#mv-face-cam').addEventListener('click', async () => {
    try {
      haltProbeCamera();
      faceSt.className = 'state-text state-warning';
      faceSt.textContent = 'Starting Camera...';
      if (!activeChallenge) {
        activeChallenge = await requestLivenessChallenge().catch(() => null);
      }
      if (faceChallengeBanner) {
        if (activeChallenge?.faceChallenge) {
          faceChallengeBanner.textContent = describeFaceChallenge(activeChallenge.faceChallenge);
          faceChallengeBanner.hidden = false;
        } else {
          faceChallengeBanner.hidden = true;
        }
      }
      await ensureFaceEngineReady();

      activeStream = await openCameraStream();
      const wrap = document.createElement('div');
      wrap.className = 'face-guide-wrap';
      const v = await createLiveVideoElement(activeStream);
      const oval = document.createElement('div');
      oval.className = 'face-guide-oval';
      const msgBadge = document.createElement('div');
      msgBadge.className = 'face-guide-status';
      msgBadge.textContent = activeChallenge?.faceChallenge
        ? describeFaceChallenge(activeChallenge.faceChallenge)
        : 'Align face in oval...';

      wrap.appendChild(v);
      wrap.appendChild(oval);
      wrap.appendChild(msgBadge);
      faceLiveWrap.innerHTML = '';
      faceLiveWrap.appendChild(wrap);
      faceLiveWrap.hidden = false;
      faceSnapBtn.hidden = false;
      faceStopBtn.hidden = false;
      faceSt.className = 'state-text state-neutral';
      faceSt.textContent = 'Live Preview';

      guidanceTimer = setInterval(async () => {
        if (!activeStream) return;
        try {
          const g = await inspectLiveFaceGuidance(v);
          msgBadge.textContent = activeChallenge?.faceChallenge && g.ready
            ? `${g.message} · ${describeFaceChallenge(activeChallenge.faceChallenge)}`
            : g.message;
          oval.classList.toggle('ready', Boolean(g.ready));
        } catch {
          // Ignore single frame errors
        }
      }, 450);

      faceSnapBtn.onclick = async () => {
        faceSnapBtn.disabled = true;
        faceSnapBtn.textContent = activeChallenge?.faceChallenge ? 'Checking 4 Frames...' : 'Checking 3 Frames...';
        faceSt.className = 'state-text state-warning';
        faceSt.textContent = 'Analyzing Live Frames...';
        try {
          const res = await captureMultiFrameFaceFeatures(v, {
            delayMs: 260,
            challenge: activeChallenge?.faceChallenge,
          });
          haltProbeCamera();
          faceVec = res.vector;
          faceQuality = res.quality;
          currentIsTestProbe = false;
          if (gtSel.value !== 'unlabeled') gtSel.value = 'unlabeled';
          faceSt.className = `state-text ${faceQuality.spoofRiskFlag ? 'state-warning' : 'state-success'}`;
          faceSt.textContent = faceQuality.spoofRiskFlag
            ? 'Spoof Warning'
            : faceQuality.challengeCompleted
            ? 'Challenge ✓'
            : `Live ${faceQuality.frameCount || 3}-Frame ✓`;
          faceQEl.textContent = `Q:${faceQuality.faceQualityScore}/100 · Cons:${faceQuality.frameConsistencyCosine} · Motion:${faceQuality.frameMotionScore}${
            typeof faceQuality.antispoofScore === 'number' ? ` · AntiSpoof:${Math.round(faceQuality.antispoofScore * 100)}%` : ''
          }${typeof faceQuality.challengeCompleted === 'boolean' ? ` · Challenge:${faceQuality.challengeCompleted ? 'Completed' : 'Not Detected'}` : ''}`;
        } catch (err) {
          faceVec = null;
          faceQuality = null;
          faceSt.className = 'state-text state-danger';
          faceSt.textContent = err.feedbackLabel || 'Rejected';
          faceQEl.textContent = err.message;
          showToast(err.message, 'danger');
        } finally {
          faceSnapBtn.disabled = false;
          faceSnapBtn.textContent = 'Capture';
          haltProbeCamera();
        }
      };
    } catch (err) {
      haltProbeCamera();
      faceSt.className = 'state-text state-danger';
      faceSt.textContent = 'Camera Error';
      showToast(`Camera error: ${err.message}`, 'warning');
    }
  });

  faceStopBtn.addEventListener('click', () => {
    haltProbeCamera();
    faceSt.className = 'state-text state-neutral';
    faceSt.textContent = faceVec ? 'Ready' : 'Empty';
  });

  container.querySelector('#mv-face-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try { haltProbeCamera(); await setFaceRealProbe(await loadImageFile(f), 'Uploaded ✓', { captureSource: 'upload' }); }
    catch (err) { showToast(err.message, 'danger'); }
  });
  container.querySelector('#mv-face-gen')?.addEventListener('click', loadFaceMatch);
  container.querySelector('#mv-face-imp')?.addEventListener('click', loadFaceImpostor);

  container.querySelector('#mv-voice-mic').addEventListener('click', async (e) => {
    const b = e.currentTarget; b.disabled = true;
    try {
      if (!activeChallenge) {
        activeChallenge = await requestLivenessChallenge().catch(() => null);
      }
      if (voiceChallengeBanner && activeChallenge?.voicePassphrase) {
        voiceChallengeBanner.textContent = `Speak clearly: "${activeChallenge.voicePassphrase}" (acoustic replay/DR screening only; spoken-text ASR not enabled)`;
        voiceChallengeBanner.hidden = false;
      }
      const p = await recordMicrophonePCM(2400, ({ elapsedSec, totalSec }) => {
        b.textContent = `${elapsedSec.toFixed(1)}/${totalSec.toFixed(1)}s`;
      });
      setVoiceProbe(p.samples, p.sampleRate, 'Recorded ✓', 'microphone', p.wavUrl);
    } catch (err) { showToast(err.message, 'warning'); }
    finally { b.disabled = false; b.textContent = 'Mic (2.4s)'; }
  });
  container.querySelector('#mv-voice-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const p = await decodeAudioFileToPCM(f);
      setVoiceProbe(p.samples, p.sampleRate, 'Uploaded ✓', 'upload');
    } catch (err) { showToast(err.message, 'danger'); }
  });
  container.querySelector('#mv-voice-gen')?.addEventListener('click', loadVoiceMatch);
  container.querySelector('#mv-voice-imp')?.addEventListener('click', loadVoiceImpostor);

  container.querySelector('#mv-fp-file').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try { setFpProbe(await loadImageFile(f), 'Uploaded ✓', 'upload'); }
    catch (err) { showToast(err.message, 'danger'); }
  });
  container.querySelector('#mv-fp-gen')?.addEventListener('click', loadFpMatch);
  container.querySelector('#mv-fp-imp')?.addEventListener('click', loadFpImpostor);

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
      const submittedChallengeToken = activeChallenge?.challengeToken;
      activeChallenge = null;
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
        strictLiveness: Boolean(s.strictLiveness),
        modalityWeights: s.modalityWeights,
        challengeToken: submittedChallengeToken,
        samples,
        quality,
        adaptiveEnabled,
        groundTruth,
        isTestProbe: currentIsTestProbe,
      });

      const finalDecision =
        res.finalDecision ||
        (res.outcome === 'match' ? 'VERIFIED' : res.outcome === 'no_match' ? 'REJECTED' : 'INCONCLUSIVE');
      const livenessStatus =
        res.livenessStatus ||
        res.liveness?.status ||
        (res.liveness?.passed ? 'LIVENESS PASSED' : 'INCONCLUSIVE');
      const datasetCategory = currentIsTestProbe
        ? 'synthetic_qa'
        : groundTruth !== 'unlabeled'
        ? 'benchmark_eval'
        : 'operational';

      const verId = await recordVerificationMetadata({
        identityRef,
        modalities: res.modalitiesEvaluated,
        pipeline: res.pipeline,
        outcome: res.outcome,
        finalDecision,
        livenessStatus,
        livenessDecision: res.livenessDecision,
        challengeVerified: res.challengeVerified,
        datasetCategory,
        captureFailure: false,
        reasonCode: res.reasonCode,
        score: res.score,
        confidence: res.confidence,
        identityConfidence: res.identityConfidence,
        sampleQualityScore: res.sampleQualityScore,
        livenessConfidence: res.livenessConfidence,
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
        result: `${res.pipeline} (${res.fusionPolicy}): ${finalDecision} sim=${fmtPct(res.score)} conf=${fmtPct(res.confidence)} live=${livenessStatus} gt=${groundTruth} (${res.processingTimeMs}ms)`,
        requestId: res.requestId,
      });

      if (livenessStatus === 'LIVENESS FAILED' || (res.risk?.score ?? 0) >= 50 || res.conflictDetected) {
        const alertCategory =
          livenessStatus === 'LIVENESS FAILED'
            ? 'Spoofing / Liveness Failure'
            : res.conflictDetected
            ? 'Cross-Modality Conflict Detected'
            : 'High-Risk Verification Attempt';
        const alertDesc = `${identityRef} via ${res.pipeline}: decision=${finalDecision}, liveness=${livenessStatus}, similarity=${fmtPct(res.score)}, conf=${fmtPct(res.confidence)}, risk=${res.risk?.score}/100 (${res.risk?.level}). ${(res.rejectionReasons || res.liveness?.spoofSignals || []).join('; ')}`;
        await pushNotification({
          title: alertCategory,
          message: alertDesc.slice(0, 220),
          type: 'warning',
        }).catch(() => null);
        if (appState.permissions.includes('manage_alerts')) {
          await createSecurityAlert({
            severity: (res.risk?.score ?? 0) >= 75 || livenessStatus === 'LIVENESS FAILED' ? 'high' : 'medium',
            category: alertCategory,
            description: alertDesc,
            assignedTo: appState.fbUser?.uid || '',
          }).catch(() => null);
        }
      }

      const bannerVariant =
        finalDecision === 'VERIFIED' ? 'verified' : finalDecision === 'REJECTED' ? 'rejected' : 'inconclusive';
      const outcomeCls =
        finalDecision === 'VERIFIED' ? 'state-success' : finalDecision === 'REJECTED' ? 'state-danger' : 'state-warning';
      // Honest Liveness color rule: GREEN ONLY if strictly LIVENESS PASSED
      const liveCls =
        livenessStatus === 'LIVENESS PASSED'
          ? 'state-success'
          : livenessStatus === 'LIVENESS FAILED'
          ? 'state-danger'
          : 'state-warning';
      const riskLvl = res.risk?.level || 'low';
      const riskCls = riskLvl === 'critical' || riskLvl === 'high' ? 'state-danger' : riskLvl === 'medium' ? 'state-warning' : 'state-success';
      const confCls = res.confidenceBand === 'high' ? 'state-success' : res.confidenceBand === 'moderate' ? 'state-warning' : 'state-danger';
      const modRows = Object.entries(res.modalityEvaluations || {});
      const fpEval = res.modalityEvaluations?.fingerprint || null;
      const fpDet = fpEval?.details || {};

      resultEl.innerHTML = `
        <section class="panel stack-md">
          <div class="decision-banner ${bannerVariant}">
            <div class="stack-sm" style="gap:4px;">
              <span class="state-text ${outcomeCls}" style="font-size:15px;">${escapeHtml(finalDecision)}</span>
              <h3 class="panel-title">${escapeHtml(res.identityRef)}</h3>
              <div class="meta-line">
                <span>Reason: <strong class="mono">${escapeHtml(res.reasonCode)}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Request: <span class="mono">${escapeHtml(res.requestId)}</span></span>
                <span aria-hidden="true">·</span>
                <span>Latency: <strong class="mono">${res.processingTimeMs ?? '—'} ms</strong></span>
                <span aria-hidden="true">·</span>
                <span>${new Date().toLocaleTimeString()}</span>
              </div>
            </div>
            ${
              appState.permissions.includes('use_ai_analyst')
                ? `<button type="button" class="btn btn-secondary btn-sm" id="mv-explain-ai">Explain with AI Analyst</button>`
                : ''
            }
          </div>

          ${res.fusionExplanation ? `<div style="font-size:13px;color:var(--text-secondary);">${escapeHtml(res.fusionExplanation)}</div>` : ''}

          <div class="kpi-strip">
            <div class="kpi-cell">
              <span class="kpi-label">Similarity Score</span>
              <span class="kpi-value">${fmtPct(res.score)}</span>
              <span class="kpi-meta">Required: ${fmtPct(res.threshold)}</span>
            </div>
            <div class="kpi-cell">
              <span class="kpi-label">Composite Confidence</span>
              <span class="kpi-value ${confCls}">${fmtPct(res.confidence || 0)}</span>
              <span class="kpi-meta" style="text-transform:capitalize;">${escapeHtml(res.confidenceBand || 'low')} certainty</span>
            </div>
            <div class="kpi-cell">
              <span class="kpi-label">Liveness Screening</span>
              <span class="kpi-value ${liveCls}" style="font-size:17px;">${escapeHtml(livenessStatus)}</span>
              <span class="kpi-meta">Score ${Math.round((res.liveness?.score ?? 0) * 100)}% · Challenge: ${res.challengeVerified ? 'Verified' : 'None'}</span>
            </div>
            <div class="kpi-cell">
              <span class="kpi-label">Risk Indicator</span>
              <span class="kpi-value ${riskCls}" style="font-size:20px;">${res.risk?.score ?? 0} / 100</span>
              <span class="kpi-meta" style="text-transform:capitalize;">${escapeHtml(riskLvl)} risk</span>
            </div>
          </div>

          <div class="confidence-split-grid">
            <div class="confidence-split-cell">
              <span class="meta-line">Identity Match Margin</span>
              <strong class="mono">${typeof res.identityConfidence === 'number' ? fmtPct(res.identityConfidence) : '—'}</strong>
            </div>
            <div class="confidence-split-cell">
              <span class="meta-line">Sample Quality Index</span>
              <strong class="mono">${typeof res.sampleQualityScore === 'number' ? fmtPct(res.sampleQualityScore) : '—'}</strong>
            </div>
            <div class="confidence-split-cell">
              <span class="meta-line">Liveness Integrity</span>
              <strong class="mono">${typeof res.livenessConfidence === 'number' ? fmtPct(res.livenessConfidence) : '—'}</strong>
            </div>
          </div>

          <div class="progress-track">
            <div class="progress-fill ${finalDecision === 'VERIFIED' ? 'success' : 'danger'}" style="width:${Math.min(100, Math.round(res.score * 100))}%"></div>
          </div>

          ${
            res.trustedSensorAttestation === false && (livenessStatus === 'NOT SUPPORTED' || livenessStatus === 'INCONCLUSIVE')
              ? `<div class="meta-line">Sensor attestation: <span class="mono">unattested browser capture</span> — liveness is software-screened only unless an active challenge passes on live camera.</div>`
              : ''
          }

          ${
            fpEval
              ? `<section class="fp-results-panel stack-sm">
                  <div class="row-between">
                    <strong>Fingerprint Verification Panel</strong>
                    <span class="state-text ${fpEval.status === 'MATCH' ? 'state-success' : fpEval.status === 'INCONCLUSIVE' ? 'state-warning' : 'state-danger'}">${escapeHtml(fpDet.decision || fpEval.status || (fpEval.passed ? 'MATCH' : 'NO MATCH'))}</span>
                  </div>
                  <div class="fp-meta-grid">
                    <div><span class="meta-line">Similarity</span><div class="mono"><strong>${fmtPct(fpEval.score)}</strong> (Thr ${fmtPct(fpEval.threshold)})</div></div>
                    <div><span class="meta-line">Image Quality</span><div class="mono"><strong>${fpDet.qualityScore ?? fpEval.qualityScore}/100</strong> (${escapeHtml(fpDet.qualityLabel || 'Evaluated')})</div></div>
                    <div><span class="meta-line">Minutiae Matched</span><div class="mono"><strong>${fpDet.matchedMinutiae ?? 0}</strong> / ${fpDet.probeMinutiae ?? 0} probe (${fpDet.estimatedRotationDeg ?? 0}°)</div></div>
                    <div><span class="meta-line">Ridge Coherence &amp; Wavelength</span><div class="mono">${fpDet.meanCoherence ?? '—'} · ${fpDet.meanWavelengthPx ?? '—'}px</div></div>
                    <div><span class="meta-line">Template Status</span><div class="mono">${escapeHtml(fpDet.templateStatus || (fpDet.validPrint === false ? 'Insufficient Features' : 'Valid Minutiae Template'))}</div></div>
                    <div><span class="meta-line">Latency</span><div class="mono">${res.processingTimeMs ?? '—'} ms</div></div>
                  </div>
                  ${fpDet.decisionReason ? `<div class="meta-line">${escapeHtml(fpDet.decisionReason)}</div>` : ''}
                </section>`
              : ''
          }

          ${
            res.conflictDetected
              ? `<div class="notice-strip danger"><div><strong>Cross-Modality Conflict Detected</strong><div>${escapeHtml((res.conflictDetails || []).join(' '))}</div></div></div>`
              : ''
          }
          ${
            res.legacyCompatibility
              ? `<div class="notice-strip warning"><div><strong>Legacy Template Compatibility Mode</strong><div>This identity uses <span class="mono">${escapeHtml(res.featureVersion)}</span>. Re-enroll in Enrollment to upgrade to the latest extractors.</div></div></div>`
              : ''
          }
          ${
            (res.rejectionReasons || []).length > 0
              ? `<div class="notice-strip warning"><div><strong>Decision Explanation</strong><div>${res.rejectionReasons.map((r) => `• ${escapeHtml(r)}`).join('<br/>')}</div></div></div>`
              : ''
          }

          ${
            modRows.length > 0
              ? `<div class="table-wrap">
                  <table class="data-table">
                    <thead>
                      <tr>
                        <th>Modality</th>
                        <th class="num-col">Similarity</th>
                        <th class="num-col">Threshold</th>
                        <th class="num-col">Quality</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${modRows
                        .map(([mod, ev]) => {
                          const st = ev.status || (ev.passed ? 'MATCH' : 'NO MATCH');
                          const stCls = st === 'MATCH' ? 'state-success' : st === 'INCONCLUSIVE' ? 'state-warning' : 'state-danger';
                          return `
                          <tr>
                            <td style="text-transform:capitalize;"><strong>${escapeHtml(mod)}</strong></td>
                            <td class="num-col">${fmtPct(ev.score)}</td>
                            <td class="num-col">${fmtPct(ev.threshold)}</td>
                            <td class="num-col">${ev.qualityScore}/100</td>
                            <td><span class="state-text ${stCls}">${escapeHtml(st)}</span></td>
                          </tr>`;
                        })
                        .join('')}
                    </tbody>
                  </table>
                </div>`
              : ''
          }

          <details class="advanced-details">
            <summary>Advanced Details (Matcher Telemetry, Liveness &amp; Risk Factors)</summary>
            <div class="advanced-details-body" style="font-size:12.5px;">
              <div class="meta-line">
                <span>Pipeline: <strong class="mono">${escapeHtml(res.pipeline)}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Policy: <strong class="mono">${escapeHtml(res.fusionPolicy)}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Threshold: <strong class="mono">${fmtPct(res.threshold)}</strong>${res.adaptiveApplied ? ` (base ${fmtPct(res.baseThreshold)})` : ''}</span>
                <span aria-hidden="true">·</span>
                <span>Trial: <strong class="mono">${escapeHtml(groundTruth)}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Dataset: <strong class="mono">${escapeHtml(datasetCategory)}</strong></span>
              </div>

              ${
                modRows.length > 0
                  ? `<div class="stack-sm" style="gap:4px;">
                      <strong>Per-Modality Matcher Telemetry</strong>
                      ${modRows
                        .map(([mod, ev]) => {
                          const detStr =
                            mod === 'fingerprint' && typeof ev.details?.matchedMinutiae === 'number'
                              ? `${ev.details.matchedMinutiae}/${ev.details.probeMinutiae} minutiae matched · rotation ${ev.details.estimatedRotationDeg}° · coh=${ev.details.meanCoherence ?? '—'}`
                              : typeof ev.rawCosine === 'number'
                              ? `rawCos=${ev.rawCosine} (${ev.details?.dim || ''}-D vector)`
                              : 'Evaluated';
                          return `<div class="row-between"><span style="text-transform:capitalize;">${escapeHtml(mod)}</span><span class="mono">${escapeHtml(detStr)}</span></div>`;
                        })
                        .join('')}
                    </div>`
                  : ''
              }

              <div class="grid-2">
                <div class="stack-sm" style="gap:4px;">
                  <strong>Liveness Signals (${escapeHtml(livenessStatus)})</strong>
                  ${[...(res.liveness?.checks || []), ...(res.liveness?.spoofSignals || [])].map((x) => `<div>• ${escapeHtml(x)}</div>`).join('') || '<div>Checked signal integrity.</div>'}
                </div>
                <div class="stack-sm" style="gap:4px;">
                  <strong>Risk &amp; Adaptive Policy</strong>
                  ${(res.risk?.factors || []).map((f) => `<div>• ${escapeHtml(f)}</div>`).join('') || '<div>Normal baseline behavior.</div>'}
                  ${res.details?.adaptive?.reason ? `<div style="color:var(--accent);">Adaptive: ${escapeHtml(res.details.adaptive.reason)}</div>` : ''}
                </div>
              </div>
            </div>
          </details>
        </section>
      `;

      resultEl.querySelector('#mv-explain-ai')?.addEventListener('click', () => {
        navigate('ai_analyst', {
          verificationId: verId,
          analystMode: 'explain_verification',
          analystPrompt: `Explain verification result ${verId || res.requestId} for identity "${res.identityRef}" (${res.pipeline}, policy=${res.fusionPolicy}: finalDecision=${finalDecision}, liveness=${livenessStatus}, similarity=${fmtPct(res.score)}, confidence=${fmtPct(res.confidence)}, conflict=${res.conflictDetected}, threshold=${fmtPct(res.threshold)}, risk=${res.risk?.score}/100 ${res.risk?.level}, reason=${res.reasonCode}). Recommend next steps.`,
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
        <h1 class="page-title">Identities</h1>
        <p class="page-subtitle">Manage enrolled biometric profiles, launch verifications or searches, and process deletion governance.</p>
      </div>
      ${appState.permissions.includes('create_identity') ? `<div class="page-actions"><button type="button" class="btn btn-primary" id="id-enroll-btn">Enroll Identity</button></div>` : ''}
    </div>

    <section class="panel stack-md">
      <div class="row-between">
        <div class="row-wrap" style="flex:1;">
          <input type="search" class="input responsive-search" id="id-search" placeholder="Search identity ID or name..." />
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
      btn.addEventListener('click', () => {
        const ref = btn.dataset.toggleId;
        const nextSt = btn.dataset.nextSt;
        const activating = nextSt === 'active';
        openModal({
          title: `${activating ? 'Reactivate' : 'Deactivate'} Identity ${ref}?`,
          bodyHtml: `<p style="font-size:13.5px;color:var(--text-secondary);">Confirm status change for <strong class="mono">${escapeHtml(ref)}</strong> to <strong class="mono">${escapeHtml(nextSt)}</strong>.${activating ? ' This profile will become eligible for verification and search.' : ' Deactivated identities cannot be verified until reactivated.'}</p>`,
          footerButtons: [
            { label: 'Cancel', variant: 'btn-secondary' },
            {
              label: activating ? 'Confirm Reactivation' : 'Confirm Deactivation',
              variant: activating ? 'btn-primary' : 'btn-danger',
              onClick: async ({ close }) => {
                try {
                  await updateIdentityStatusOrName(ref, { status: nextSt });
                  await appendAuditLog({
                    action: activating ? 'identity_reactivated' : 'identity_deactivated',
                    resourceType: 'identity',
                    resourceId: ref,
                    result: `Status changed to ${nextSt}`,
                  });
                  close();
                  showToast(`Identity "${ref}" set to ${nextSt}.`, 'success');
                } catch (err) {
                  showToast(err.message, 'danger');
                }
              },
            },
          ],
        });
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
  let idSearchTimer = null;
  container.querySelector('#id-search').addEventListener('input', (e) => {
    clearTimeout(idSearchTimer);
    idSearchTimer = setTimeout(() => {
      searchQ = e.target.value;
      page = 1;
      drawTable();
    }, 180);
  });
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
