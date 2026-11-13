import {
  listUsersForAdmin,
  updateOwnPreferences,
  saveSystemSettings,
  appendAuditLog,
} from './firebase.js';
import {
  updateUserRoleOrStatus,
  fetchApiHealth,
  queryAiSecurityAnalyst,
} from './api.js';
import { buildBiometricAnalyticsReport } from './biometrics.js';
import { getPwaStatus, triggerPwaInstall, shareOrCopyPortableLink } from './pwa.js';
import {
  DEFAULT_THRESHOLDS,
  PERMISSION_MATRIX,
  THRESHOLD_PRESETS,
  FUSION_POLICIES,
  isAuthorizedDevAdmin,
  isDevTestingModeActive,
} from './config.js';
import { escapeHtml, fmtPct, showToast, openModal } from './ui.js';

function buildAnalystContext(appState, selectedVerId) {
  const selectedVerification = appState.verifications.find((v) => v.verificationId === selectedVerId) || null;
  const s = appState.settings || DEFAULT_THRESHOLDS;
  const activeCount = appState.identities.filter((i) => i.status === 'active').length;
  const report = buildBiometricAnalyticsReport(appState.verifications, appState.identities.length, activeCount, {
    face: s.faceThreshold ?? 0.72,
    voice: s.voiceThreshold ?? 0.70,
    fingerprint: s.fingerprintThreshold ?? 0.72,
    threeModal: s.threeModalThreshold ?? 0.74,
  });

  return {
    organization: s.organizationName || 'BioGuard X Research',
    thresholds: s,
    enrolledIdentitiesCount: appState.identities.length,
    analyticsSummary: {
      totalAttempts: report.totalAttempts,
      operationalVerificationSuccessRate: report.operationalVerificationSuccessRate,
      labeledAttempts: report.labeledAttempts,
      unlabeledAttempts: report.unlabeledAttempts,
      insufficientData: report.classification.insufficientData,
      classificationAccuracy: report.classification.sampleCount > 0 ? report.classification.accuracy : null,
      tar: report.classification.sampleCount > 0 ? report.classification.tar : null,
      far: report.classification.sampleCount > 0 ? report.classification.far : null,
      frr: report.classification.sampleCount > 0 ? report.classification.frr : null,
      eer: report.classification.roc.length > 0 ? report.classification.eer : null,
      livenessSuccessRate: report.livenessKnownCount > 0 ? report.livenessSuccessRate : null,
      conflictsCount: report.conflictCount,
      avgProcessingTimeMs: report.latency.avgMs,
    },
    selectedVerification: selectedVerification
      ? {
          verificationId: selectedVerification.verificationId,
          identityRef: selectedVerification.identityRef,
          pipeline: selectedVerification.pipeline,
          modalities: selectedVerification.modalities,
          outcome: selectedVerification.outcome,
          score: selectedVerification.score,
          confidence: selectedVerification.confidence,
          confidenceBand: selectedVerification.confidenceBand,
          conflictDetected: selectedVerification.conflictDetected,
          processingTimeMs: selectedVerification.processingTimeMs,
          featureVersion: selectedVerification.featureVersion,
          groundTruth: selectedVerification.groundTruth,
          riskScore: selectedVerification.riskScore,
          riskLevel: selectedVerification.riskLevel,
          livenessPassed: selectedVerification.livenessPassed,
          livenessScore: selectedVerification.livenessScore,
          adaptiveApplied: selectedVerification.adaptiveApplied,
          reasonCode: selectedVerification.reasonCode,
        }
      : null,
    recentVerifications: appState.verifications.slice(0, 12).map((v) => ({
      verificationId: v.verificationId,
      identityRef: v.identityRef,
      pipeline: v.pipeline,
      outcome: v.outcome,
      score: v.score,
      confidence: v.confidence,
      conflictDetected: v.conflictDetected,
      processingTimeMs: v.processingTimeMs,
      groundTruth: v.groundTruth,
      riskScore: v.riskScore,
      riskLevel: v.riskLevel,
      livenessPassed: v.livenessPassed,
      reasonCode: v.reasonCode,
    })),
    securityAlerts: appState.alerts.slice(0, 10).map((a) => ({
      alertId: a.alertId,
      severity: a.severity,
      category: a.category,
      status: a.status,
      description: a.description,
    })),
    recentAuditEvents: appState.auditLogs.slice(0, 10).map((l) => ({
      action: l.action,
      resourceType: l.resourceType,
      resourceId: l.resourceId,
      result: l.result,
    })),
  };
}

// AI SECURITY ANALYST
export function renderAiAnalyst(container, { appState }) {
  if (!appState.permissions.includes('use_ai_analyst')) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>AI Security Analyst requires Operator, Security Analyst, Administrator, or Super Admin privileges.</div></div></div>`;
    return;
  }

  const verifications = appState.verifications || [];
  let selectedVerId =
    verifications.find((v) => v.verificationId === appState.selectedVerificationId)?.verificationId ||
    verifications[0]?.verificationId ||
    '';
  appState.selectedVerificationId = '';

  const geminiReady = appState.health?.gemini_configured !== false;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">AI Security Analyst</h1>
        <p class="page-subtitle">Explain verification scores, investigate spoofing or velocity anomalies, and summarize incidents grounded in live telemetry.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-ghost" id="ai-clear-btn">Clear Thread</button>
      </div>
    </div>

    <div class="notice-strip warning">
      <div>
        <strong>Advisory Security Intelligence Only</strong>
        <div>AI-generated explanations and risk assessments are advisory only—they are never guaranteed proof of identity and never override biometric thresholds or RBAC controls.</div>
      </div>
    </div>

    ${
      !geminiReady
        ? `<div class="notice-strip danger"><div><strong>Gemini API Key Missing</strong><div>Configure <span class="mono">GEMINI_API_KEY</span> in Settings &gt; Secrets to enable AI Security Analyst responses.</div></div></div>`
        : ''
    }

    <section class="panel stack-md">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Guided Security Investigations</h2>
          <p class="panel-subtitle">Select a verification record or trigger an incident investigation</p>
        </div>
      </div>

      <div class="row-between">
        <div class="row-wrap" style="flex:1;min-width:260px;">
          <select class="select" id="ai-ver-select" style="max-width:420px;" ${verifications.length === 0 ? 'disabled' : ''}>
            ${
              verifications.length === 0
                ? `<option value="">No verification records available yet</option>`
                : verifications
                    .slice(0, 25)
                    .map(
                      (v) =>
                        `<option value="${escapeHtml(v.verificationId)}" ${v.verificationId === selectedVerId ? 'selected' : ''}>${escapeHtml(v.identityRef)} · ${escapeHtml(v.pipeline)} · ${escapeHtml(v.outcome)} (${fmtPct(v.score || 0)})</option>`
                    )
                    .join('')
            }
          </select>
          <button type="button" class="btn btn-secondary" id="ai-btn-explain" ${verifications.length === 0 ? 'disabled' : ''}>Explain Verification</button>
        </div>

        <div class="row-wrap">
          <button type="button" class="btn btn-secondary" id="ai-btn-investigate">Investigate Suspicious Activity</button>
          <button type="button" class="btn btn-secondary" id="ai-btn-summarize">Summarize Incidents &amp; Next Steps</button>
        </div>
      </div>
    </section>

    <section class="panel stack-md">
      <div class="chat-thread" id="ai-thread"></div>

      <form id="ai-form" class="row-wrap" style="align-items:stretch;">
        <input class="input" id="ai-input" style="flex:1;" maxlength="2000" placeholder="Ask about verification scores, liveness rejections, risk spikes, or remediation steps..." />
        <button type="submit" class="btn btn-primary" id="ai-send">Analyze</button>
      </form>
    </section>
  `;

  const threadEl = container.querySelector('#ai-thread');
  const verSel = container.querySelector('#ai-ver-select');
  const inputEl = container.querySelector('#ai-input');
  const sendBtn = container.querySelector('#ai-send');

  const drawThread = () => {
    if (!appState.aiHistory.length) {
      threadEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-title">No active investigation messages</div>
          <div class="empty-desc">Use the guided investigation buttons above or ask a question about recent verifications, liveness flags, or open security alerts.</div>
        </div>
      `;
      return;
    }
    threadEl.innerHTML = appState.aiHistory
      .map(
        (m) => `
      <div class="chat-msg ${m.role === 'user' ? 'user' : 'model'}">
        <span class="meta-line" style="font-size:11.5px;font-weight:600;">${m.role === 'user' ? 'Operator' : 'AI Security Analyst'}</span>
        <div class="chat-body">${escapeHtml(m.text)}</div>
      </div>`
      )
      .join('');
    threadEl.scrollTop = threadEl.scrollHeight;
  };

  drawThread();

  let busy = false;
  const submitAnalysis = async (prompt, mode = 'chat') => {
    const clean = String(prompt || '').trim();
    if (!clean || busy) return;
    busy = true;
    sendBtn.disabled = true;
    sendBtn.textContent = 'Analyzing...';

    const historySnapshot = appState.aiHistory.slice(-6);
    appState.aiHistory.push({ role: 'user', text: clean });
    drawThread();

    try {
      const res = await queryAiSecurityAnalyst({
        mode,
        message: clean,
        history: historySnapshot,
        context: buildAnalystContext(appState, verSel?.value || selectedVerId),
      });
      appState.aiHistory.push({ role: 'model', text: res.reply });
      drawThread();
      await appendAuditLog({
        action: 'ai_analyst_query',
        resourceType: 'ai_analyst',
        resourceId: mode,
        result: `Completed advisory query (${clean.slice(0, 60)})`,
      }).catch(() => null);
    } catch (err) {
      appState.aiHistory.push({
        role: 'model',
        text: `Analysis error: ${err.message}`,
      });
      drawThread();
      showToast(err.message, 'danger');
    } finally {
      busy = false;
      sendBtn.disabled = false;
      sendBtn.textContent = 'Analyze';
    }
  };

  verSel?.addEventListener('change', () => {
    selectedVerId = verSel.value;
  });

  container.querySelector('#ai-btn-explain')?.addEventListener('click', () => {
    const v = verifications.find((x) => x.verificationId === verSel.value);
    if (!v) return;
    submitAnalysis(
      `Explain verification record ${v.verificationId} for identity "${v.identityRef}" (${v.pipeline}: outcome=${v.outcome}, score=${fmtPct(v.score || 0)}, livenessPassed=${v.livenessPassed}, risk=${v.riskScore ?? 'n/a'}/100, reason=${v.reasonCode}) and recommend next steps.`,
      'explain_verification'
    );
  });

  container.querySelector('#ai-btn-investigate')?.addEventListener('click', () => {
    submitAnalysis(
      'Investigate suspicious verification activity, liveness/spoofing anomalies, and high-risk attempts in the current telemetry context. Highlight specific identity references and recommended actions.',
      'investigate_activity'
    );
  });

  container.querySelector('#ai-btn-summarize')?.addEventListener('click', () => {
    submitAnalysis(
      'Summarize open security incidents, recent verification trends, and prioritized remediation steps for the security operations team.',
      'summarize_incidents'
    );
  });

  container.querySelector('#ai-clear-btn').addEventListener('click', () => {
    if (!appState.aiHistory.length) {
      showToast('Investigation thread is already empty.', 'neutral');
      return;
    }
    openModal({
      title: 'Clear Investigation Thread?',
      bodyHtml: `<p style="font-size:13.5px;color:var(--text-secondary);">Clear all ${appState.aiHistory.length} message(s) from the current AI Security Analyst session? Persisted Firestore audit logs remain intact.</p>`,
      footerButtons: [
        { label: 'Cancel', variant: 'btn-secondary' },
        {
          label: 'Clear Thread',
          variant: 'btn-danger',
          onClick: ({ close }) => {
            appState.aiHistory = [];
            drawThread();
            close();
          },
        },
      ],
    });
  });

  container.querySelector('#ai-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const val = inputEl.value.trim();
    if (!val) return;
    inputEl.value = '';
    submitAnalysis(val, 'chat');
  });

  if (appState.analystInitialPrompt) {
    const seedPrompt = appState.analystInitialPrompt;
    const seedMode = appState.analystInitialMode || 'chat';
    appState.analystInitialPrompt = '';
    appState.analystInitialMode = 'chat';
    submitAnalysis(seedPrompt, seedMode);
  }
}

// ACCESS CONTROL
export async function renderAccessControl(container, { appState }) {
  const canManageRoles = appState.permissions.includes('manage_roles');

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Access Control &amp; Permissions</h1>
        <p class="page-subtitle">Role-based access control enforced on both the API server and Cloud Firestore security rules.</p>
      </div>
    </div>

    <section class="panel stack-md">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Role Permission Matrix</h2>
          <p class="panel-subtitle">Your active role: <strong class="mono">${escapeHtml(appState.profile?.role || 'viewer')}</strong></p>
        </div>
      </div>

      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Capability</th>
              <th>Super Admin</th>
              <th>Administrator</th>
              <th>Security Analyst</th>
              <th>Operator</th>
              <th>Viewer</th>
            </tr>
          </thead>
          <tbody>
            ${PERMISSION_MATRIX.map(
              (p) => `
              <tr>
                <td><strong>${escapeHtml(p.label)}</strong></td>
                ${['super_admin', 'administrator', 'security_analyst', 'operator', 'viewer']
                  .map((r) => {
                    const ok = p.roles.includes(r);
                    return `<td><span class="state-text ${ok ? 'state-success' : 'state-neutral'}">${ok ? 'Allowed' : 'Denied'}</span></td>`;
                  })
                  .join('')}
              </tr>`
            ).join('')}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel stack-md" id="ac-users-panel">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">${canManageRoles ? 'User &amp; Role Management' : 'Your Isolated Account Workspace'}</h2>
          <p class="panel-subtitle">${canManageRoles ? 'Assign operator roles or update account access status' : 'Every Google account operates in its own isolated Firestore workspace and AES-256-GCM biometric vault.'}</p>
        </div>
      </div>
      <div id="ac-users-body" class="panel-subtitle">${
        canManageRoles
          ? 'Loading user accounts from Firestore...'
          : `Signed in as <strong class="mono">${escapeHtml(appState.profile?.email || '')}</strong> · Workspace UID: <strong class="mono">${escapeHtml(appState.fbUser?.uid || '')}</strong> · Data path: <span class="mono">users/${escapeHtml(appState.fbUser?.uid || '')}/...</span>`
      }</div>
    </section>
  `;

  if (!canManageRoles) return;

  const usersBody = container.querySelector('#ac-users-body');
  try {
    const users = await listUsersForAdmin();
    if (!users.length) {
      usersBody.textContent = 'No user profiles found.';
      return;
    }
    usersBody.innerHTML = `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Save</th>
            </tr>
          </thead>
          <tbody>
            ${users
              .map(
                (u) => `
              <tr>
                <td><strong>${escapeHtml(u.displayName)}</strong><div class="mono" style="font-size:11.5px;color:var(--text-muted);">${escapeHtml(u.uid)}</div></td>
                <td class="mono" style="font-size:12.5px;">${escapeHtml(u.email)}</td>
                <td>
                  <select class="select" data-u-role="${escapeHtml(u.uid)}" style="min-height:32px;padding:4px 8px;width:auto;">
                    ${['super_admin', 'administrator', 'security_analyst', 'operator', 'viewer']
                      .map((r) => `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r}</option>`)
                      .join('')}
                  </select>
                </td>
                <td>
                  <select class="select" data-u-status="${escapeHtml(u.uid)}" style="min-height:32px;padding:4px 8px;width:auto;">
                    <option value="active" ${u.status === 'active' ? 'selected' : ''}>active</option>
                    <option value="suspended" ${u.status === 'suspended' ? 'selected' : ''}>suspended</option>
                  </select>
                </td>
                <td>
                  <button type="button" class="btn btn-secondary btn-sm" data-save-user="${escapeHtml(u.uid)}">Apply</button>
                </td>
              </tr>`
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;

    usersBody.querySelectorAll('[data-save-user]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const uid = btn.dataset.saveUser;
        const role = usersBody.querySelector(`[data-u-role="${uid}"]`).value;
        const status = usersBody.querySelector(`[data-u-status="${uid}"]`).value;
        openModal({
          title: 'Update Account Access?',
          bodyHtml: `<p style="font-size:13.5px;color:var(--text-secondary);">Apply role <strong class="mono">${escapeHtml(role)}</strong> and status <strong class="mono">${escapeHtml(status)}</strong> to user <strong class="mono">${escapeHtml(uid)}</strong>?</p>`,
          footerButtons: [
            { label: 'Cancel', variant: 'btn-secondary' },
            {
              label: 'Confirm Update',
              variant: status === 'suspended' ? 'btn-danger' : 'btn-primary',
              onClick: async ({ close }) => {
                btn.disabled = true;
                try {
                  await updateUserRoleOrStatus(uid, { role, status });
                  await appendAuditLog({
                    action: 'user_role_updated',
                    resourceType: 'user',
                    resourceId: uid,
                    result: `role=${role}, status=${status}`,
                  });
                  close();
                  showToast(`Updated role and status for ${uid}.`, 'success');
                } catch (err) {
                  showToast(err.message, 'danger');
                } finally {
                  btn.disabled = false;
                }
              },
            },
          ],
        });
      });
    });
  } catch (err) {
    usersBody.innerHTML = `<div class="notice-strip danger"><div>${escapeHtml(err.message)}</div></div>`;
  }
}

// SETTINGS & ADAPTATION PROFILES
export function renderSettings(container, { appState, navigate, applyTheme, setDevTestingMode }) {
  const profile = appState.profile || {};
  const settings = appState.settings || { ...DEFAULT_THRESHOLDS };
  const isAdmin = appState.permissions.includes('change_settings');
  const canWorkflows = appState.permissions.includes('manage_workflows');
  const canDevMode = isAuthorizedDevAdmin(appState);
  const devModeActive = isDevTestingModeActive(appState);
  const pwa = getPwaStatus();

  let selectedPresetId =
    THRESHOLD_PRESETS.find(
      (p) =>
        Math.abs(p.faceThreshold - Number(settings.faceThreshold)) < 0.001 &&
        Math.abs(p.voiceThreshold - Number(settings.voiceThreshold)) < 0.001 &&
        Math.abs(p.fingerprintThreshold - Number(settings.fingerprintThreshold)) < 0.001 &&
        Math.abs(p.threeModalThreshold - Number(settings.threeModalThreshold)) < 0.001
    )?.id || 'custom';

  const activePolicy = settings.fusionPolicy || 'hierarchical_adaptive';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Settings</h1>
        <p class="page-subtitle">Manage account preferences, biometric fusion presets, platform diagnostics, and advanced administration.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-secondary" id="st-refresh-health">Refresh Diagnostics</button>
      </div>
    </div>

    <div class="grid-2">
      <form id="st-profile-form" class="panel stack-md">
        <div class="panel-header">
          <div><h2 class="panel-title">Account Preferences</h2><p class="panel-subtitle">Google / Firebase session profile</p></div>
        </div>
        <div class="form-grid">
          <div class="form-field">
            <label class="field-label" for="st-name">Display Name</label>
            <input class="input" id="st-name" required maxlength="120" value="${escapeHtml(profile.displayName || '')}" />
          </div>
          <div class="form-field">
            <label class="field-label" for="st-theme">Interface Theme</label>
            <select class="select" id="st-theme">
              <option value="dark" ${profile.theme !== 'light' ? 'selected' : ''}>Dark Navy</option>
              <option value="light" ${profile.theme === 'light' ? 'selected' : ''}>Light</option>
            </select>
          </div>
          <div class="form-field">
            <label class="field-label">Google Email</label>
            <input class="input mono" disabled value="${escapeHtml(profile.email || '')}" />
          </div>
          <div class="form-field">
            <label class="field-label">Assigned Role</label>
            <input class="input mono" disabled value="${escapeHtml(profile.role || 'viewer')}" />
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="align-self:flex-start;">Save Preferences</button>
      </form>

      <section class="panel stack-md">
        <div class="panel-header">
          <div><h2 class="panel-title">System Status &amp; App Install</h2><p class="panel-subtitle">Core API, database, encryption, and offline shell</p></div>
        </div>
        <div class="divider-list" style="font-size:13.5px;">
          <div class="divider-row"><span>Biometric Verification API</span><span class="state-text ${appState.health?.status === 'ok' ? 'state-success' : 'state-danger'}">${appState.health?.status === 'ok' ? 'Healthy' : 'Unreachable'}</span></div>
          <div class="divider-row"><span>Cloud Firestore Database</span><span class="state-text ${appState.firestoreOk ? 'state-success' : 'state-danger'}">${appState.firestoreOk ? 'Connected' : 'Offline'}</span></div>
          <div class="divider-row"><span>Encrypted Biometric Vault</span><span class="state-text ${appState.health?.vault_ready ? 'state-success' : 'state-warning'}">${appState.health?.vault_ready ? 'AES-256-GCM Active' : 'Unavailable'}</span></div>
          <div class="divider-row"><span>AI Security Analyst</span><span class="state-text ${appState.health?.gemini_configured ? 'state-success' : 'state-warning'}">${appState.health?.gemini_configured ? 'Ready' : 'Not Configured'}</span></div>
          <div class="divider-row">
            <span>Portable App Access (${escapeHtml(pwa.platformLabel || 'Web')})</span>
            <span class="row-wrap">
              <span class="mono" style="font-size:12px;">${pwa.standalone ? 'Installed' : pwa.swRegistered ? 'Offline Ready' : 'Browser Session'}</span>
              ${!pwa.standalone ? `<button type="button" class="btn btn-secondary btn-sm" id="st-pwa-install">Install App</button>` : ''}
              <button type="button" class="btn btn-ghost btn-sm" id="st-share-link">Share / Copy Link</button>
            </span>
          </div>
        </div>
        <details class="advanced-details">
          <summary>Advanced Details (Engine Versions)</summary>
          <div class="advanced-details-body" style="font-size:12.5px;">
            <div class="row-between"><span>Biometric Engines</span><span class="mono">FaceRes-1024D · CMVN-96D · Minutiae-RANSAC</span></div>
            <div class="row-between"><span>Feature Version</span><span class="mono">${escapeHtml(appState.health?.feature_version || 'v2.0-multimodal')}</span></div>
          </div>
        </details>
      </section>
    </div>

    <form id="st-org-form" class="panel stack-md">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Security Policy &amp; Verification Thresholds</h2>
          <p class="panel-subtitle">${isAdmin ? 'Select a security preset and fusion strategy for verification checks.' : 'Operator or Administrator privileges are required to modify policy thresholds.'}</p>
        </div>
      </div>

      <div class="preset-grid" id="st-presets">
        ${THRESHOLD_PRESETS.map(
          (p) => `
          <button
            type="button"
            class="preset-btn ${selectedPresetId === p.id ? 'active' : ''}"
            data-preset="${p.id}"
            ${isAdmin ? '' : 'disabled'}
          >
            <strong style="font-size:14px;">${escapeHtml(p.label)}</strong>
            <span style="font-size:12.5px;color:var(--text-secondary);">${escapeHtml(p.summary)}</span>
            <span class="mono" style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">Face ${p.faceThreshold} · Voice ${p.voiceThreshold} · FP ${p.fingerprintThreshold}</span>
          </button>`
        ).join('')}
      </div>

      <div class="form-grid">
        <div class="form-field">
          <label class="field-label" for="st-fusion-policy">Default Fusion Policy</label>
          <select class="select" id="st-fusion-policy" ${isAdmin ? '' : 'disabled'}>
            ${FUSION_POLICIES.map((fp) => `<option value="${fp.id}" ${activePolicy === fp.id ? 'selected' : ''}>${escapeHtml(fp.label)}</option>`).join('')}
          </select>
        </div>
        <div class="form-field">
          <label class="field-label" for="st-org">Workspace Name</label>
          <input class="input" id="st-org" ${isAdmin ? '' : 'disabled'} value="${escapeHtml(settings.organizationName)}" />
        </div>
      </div>

      <details class="advanced-details">
        <summary>Advanced Threshold Calibration (Face, Voice, Fingerprint &amp; Hold Window)</summary>
        <div class="advanced-details-body">
          <div class="form-grid">
            <div class="form-field">
              <label class="field-label" for="st-f-thr">Face Threshold (0.30–0.98)</label>
              <input class="input mono" id="st-f-thr" type="number" step="0.01" min="0.3" max="0.98" ${isAdmin ? '' : 'disabled'} value="${settings.faceThreshold}" />
            </div>
            <div class="form-field">
              <label class="field-label" for="st-v-thr">Voice Threshold (0.30–0.98)</label>
              <input class="input mono" id="st-v-thr" type="number" step="0.01" min="0.3" max="0.98" ${isAdmin ? '' : 'disabled'} value="${settings.voiceThreshold}" />
            </div>
            <div class="form-field">
              <label class="field-label" for="st-fp-thr">Fingerprint Threshold (0.30–0.98)</label>
              <input class="input mono" id="st-fp-thr" type="number" step="0.01" min="0.3" max="0.98" ${isAdmin ? '' : 'disabled'} value="${settings.fingerprintThreshold}" />
            </div>
            <div class="form-field">
              <label class="field-label" for="st-3-thr">Three-Modal Threshold (0.30–0.98)</label>
              <input class="input mono" id="st-3-thr" type="number" step="0.01" min="0.3" max="0.98" ${isAdmin ? '' : 'disabled'} value="${settings.threeModalThreshold}" />
            </div>
            <div class="form-field">
              <label class="field-label" for="st-hold">Max Temporary Hold (Hours, 1–4)</label>
              <input class="input mono" id="st-hold" type="number" min="1" max="4" ${isAdmin ? '' : 'disabled'} value="${settings.maxHoldHours}" />
            </div>
          </div>
        </div>
      </details>
      ${isAdmin ? '<button type="submit" class="btn btn-primary" style="align-self:flex-start;">Save Organization Policy</button>' : ''}
    </form>

    ${
      canWorkflows || canDevMode
        ? `
      <section class="panel stack-md">
        <div class="panel-header">
          <div>
            <h2 class="panel-title">Advanced Administration</h2>
            <p class="panel-subtitle">Workflow automation and authorized developer QA validation controls</p>
          </div>
        </div>
        <div class="divider-list">
          ${
            canWorkflows
              ? `
            <div class="divider-row">
              <div class="stack-sm" style="gap:2px;">
                <strong>Automation Center</strong>
                <span class="meta-line">${appState.workflows.length} event-driven Firestore workflow(s) configured</span>
              </div>
              <button type="button" class="btn btn-secondary btn-sm" id="st-open-automation">Open Automation Center</button>
            </div>`
              : ''
          }
          ${
            canDevMode
              ? `
            <div class="divider-row">
              <div class="stack-sm" style="gap:2px;flex:1;">
                <strong>Developer / Testing Mode</strong>
                <span class="meta-line">Administrator-only mode that exposes synthetic QA sample loaders in Enrollment and Verification. Synthetic probes are flagged <span class="mono">isTestProbe=true</span> and excluded from operational metrics.</span>
              </div>
              <div class="row-wrap">
                <span class="state-text ${devModeActive ? 'state-warning' : 'state-neutral'}">${devModeActive ? 'Active' : 'Disabled'}</span>
                <button type="button" class="btn ${devModeActive ? 'btn-danger' : 'btn-secondary'} btn-sm" id="st-toggle-devmode">${devModeActive ? 'Disable Dev Mode' : 'Enable Dev Mode'}</button>
              </div>
            </div>`
              : ''
          }
        </div>
      </section>`
        : ''
    }
  `;

  container.querySelector('#st-pwa-install')?.addEventListener('click', triggerPwaInstall);
  container.querySelector('#st-share-link')?.addEventListener('click', shareOrCopyPortableLink);
  container.querySelector('#st-open-automation')?.addEventListener('click', () => navigate('automation'));

  container.querySelector('#st-toggle-devmode')?.addEventListener('click', () => {
    if (!canDevMode || typeof setDevTestingMode !== 'function') return;
    if (devModeActive) {
      setDevTestingMode(false);
      showToast('Developer / Testing Mode disabled. Synthetic QA controls hidden.', 'success');
      return;
    }
    openModal({
      title: 'Enable Developer / Testing Mode?',
      bodyHtml: `<p style="font-size:13.5px;color:var(--text-secondary);">Enabling Developer / Testing Mode reveals synthetic QA test sample controls in Enrollment and Verification. All generated test probes are tagged <span class="mono">isTestProbe=true</span> so they are never counted as real biometric verifications, and Dev Mode resets automatically upon sign-out.</p>`,
      footerButtons: [
        { label: 'Cancel', variant: 'btn-secondary' },
        {
          label: 'Enable Dev Mode',
          variant: 'btn-primary',
          onClick: ({ close }) => {
            setDevTestingMode(true);
            close();
            showToast('Developer / Testing Mode enabled for this session.', 'neutral');
          },
        },
      ],
    });
  });

  container.querySelectorAll('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const preset = THRESHOLD_PRESETS.find((p) => p.id === btn.dataset.preset);
      if (!preset) return;
      selectedPresetId = preset.id;
      container.querySelectorAll('[data-preset]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      container.querySelector('#st-f-thr').value = preset.faceThreshold;
      container.querySelector('#st-v-thr').value = preset.voiceThreshold;
      container.querySelector('#st-fp-thr').value = preset.fingerprintThreshold;
      container.querySelector('#st-3-thr').value = preset.threeModalThreshold;
      showToast(`Applied "${preset.label}" thresholds. Save to persist.`, 'neutral');
    });
  });

  ['#st-f-thr', '#st-v-thr', '#st-fp-thr', '#st-3-thr'].forEach((sel) => {
    container.querySelector(sel)?.addEventListener('input', () => {
      selectedPresetId = 'custom';
      container.querySelectorAll('[data-preset]').forEach((b) => b.classList.remove('active'));
    });
  });

  container.querySelector('#st-profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const displayName = container.querySelector('#st-name').value.trim();
    const theme = container.querySelector('#st-theme').value;
    try {
      await updateOwnPreferences({ displayName, theme });
      appState.profile.displayName = displayName;
      appState.profile.theme = theme;
      applyTheme(theme);
      showToast('Preferences saved.', 'success');
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });

  container.querySelector('#st-org-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!isAdmin) return;
    const cfg = {
      organizationName: container.querySelector('#st-org').value.trim(),
      fusionPolicy: container.querySelector('#st-fusion-policy').value,
      securityPreset: selectedPresetId,
      maxHoldHours: Number(container.querySelector('#st-hold').value),
      faceThreshold: Number(container.querySelector('#st-f-thr').value),
      voiceThreshold: Number(container.querySelector('#st-v-thr').value),
      fingerprintThreshold: Number(container.querySelector('#st-fp-thr').value),
      threeModalThreshold: Number(container.querySelector('#st-3-thr').value),
    };
    openModal({
      title: 'Save Organization Security Policy?',
      bodyHtml: `<p style="font-size:13.5px;color:var(--text-secondary);">Update active fusion policy to <strong class="mono">${escapeHtml(cfg.fusionPolicy)}</strong> (${escapeHtml(cfg.securityPreset)}) with thresholds Face=${cfg.faceThreshold}, Voice=${cfg.voiceThreshold}, Fingerprint=${cfg.fingerprintThreshold}?</p>`,
      footerButtons: [
        { label: 'Cancel', variant: 'btn-secondary' },
        {
          label: 'Confirm Policy Save',
          variant: 'btn-primary',
          onClick: async ({ close }) => {
            try {
              await saveSystemSettings(cfg);
              appState.settings = cfg;
              await appendAuditLog({
                action: 'system_settings_updated',
                resourceType: 'system_settings',
                resourceId: 'default',
                result: `Policy=${cfg.fusionPolicy} (${cfg.securityPreset}) · F=${cfg.faceThreshold}, V=${cfg.voiceThreshold}, FP=${cfg.fingerprintThreshold}`,
              });
              close();
              showToast('Organization policy saved.', 'success');
            } catch (err) {
              showToast(err.message, 'danger');
            }
          },
        },
      ],
    });
  });

  container.querySelector('#st-refresh-health').addEventListener('click', async () => {
    try {
      appState.health = await fetchApiHealth();
      renderSettings(container, { appState, navigate, applyTheme, setDevTestingMode });
      showToast('Diagnostics refreshed.', 'success');
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });
}
