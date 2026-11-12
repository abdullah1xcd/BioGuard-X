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
import {
  DEFAULT_THRESHOLDS,
  PERMISSION_MATRIX,
  THRESHOLD_PRESETS,
} from './config.js';
import { escapeHtml, fmtPct, showToast } from './ui.js';

function buildAnalystContext(appState, selectedVerId) {
  const selectedVerification = appState.verifications.find((v) => v.verificationId === selectedVerId) || null;
  return {
    organization: appState.settings?.organizationName || 'BioGuard X Research',
    thresholds: appState.settings || DEFAULT_THRESHOLDS,
    enrolledIdentitiesCount: appState.identities.length,
    selectedVerification: selectedVerification
      ? {
          verificationId: selectedVerification.verificationId,
          identityRef: selectedVerification.identityRef,
          pipeline: selectedVerification.pipeline,
          modalities: selectedVerification.modalities,
          outcome: selectedVerification.outcome,
          score: selectedVerification.score,
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
    appState.aiHistory = [];
    drawThread();
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
          <h2 class="panel-title">User &amp; Role Management</h2>
          <p class="panel-subtitle">Assign operator roles or update account access status</p>
        </div>
      </div>
      <div id="ac-users-body" class="panel-subtitle">${canManageRoles ? 'Loading user accounts from Firestore...' : 'Administrator privileges are required to view and modify other user accounts.'}</div>
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
      btn.addEventListener('click', async () => {
        const uid = btn.dataset.saveUser;
        const role = usersBody.querySelector(`[data-u-role="${uid}"]`).value;
        const status = usersBody.querySelector(`[data-u-status="${uid}"]`).value;
        btn.disabled = true;
        try {
          await updateUserRoleOrStatus(uid, { role, status });
          await appendAuditLog({
            action: 'user_role_updated',
            resourceType: 'user',
            resourceId: uid,
            result: `role=${role}, status=${status}`,
          });
          showToast(`Updated role and status for ${uid}.`, 'success');
        } catch (err) {
          showToast(err.message, 'danger');
        } finally {
          btn.disabled = false;
        }
      });
    });
  } catch (err) {
    usersBody.innerHTML = `<div class="notice-strip danger"><div>${escapeHtml(err.message)}</div></div>`;
  }
}

// SETTINGS & ADAPTATION PROFILES
export function renderSettings(container, { appState, applyTheme }) {
  const profile = appState.profile || {};
  const settings = appState.settings || { ...DEFAULT_THRESHOLDS };
  const isAdmin = appState.permissions.includes('change_settings');

  const activePresetId =
    THRESHOLD_PRESETS.find(
      (p) =>
        Math.abs(p.faceThreshold - Number(settings.faceThreshold)) < 0.001 &&
        Math.abs(p.voiceThreshold - Number(settings.voiceThreshold)) < 0.001 &&
        Math.abs(p.fingerprintThreshold - Number(settings.fingerprintThreshold)) < 0.001 &&
        Math.abs(p.threeModalThreshold - Number(settings.threeModalThreshold)) < 0.001
    )?.id || 'custom';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Settings &amp; Configuration</h1>
        <p class="page-subtitle">Adapt appearance, verification sensitivity presets, and organization thresholds to match your deployment.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-secondary" id="st-refresh-health">Refresh Health Status</button>
      </div>
    </div>

    <div class="grid-2">
      <form id="st-profile-form" class="panel stack-md">
        <div class="panel-header">
          <div><h2 class="panel-title">Operator Preferences</h2><p class="panel-subtitle">Signed in via Google / Firebase Authentication</p></div>
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
          <div><h2 class="panel-title">System Diagnostics</h2><p class="panel-subtitle">Live status of connected services</p></div>
        </div>
        <div class="divider-list" style="font-size:13.5px;">
          <div class="divider-row"><span>Biometric Verification API</span><span class="state-text ${appState.health?.status === 'ok' ? 'state-success' : 'state-danger'}">${appState.health?.status === 'ok' ? 'Healthy' : 'Unreachable'}</span></div>
          <div class="divider-row"><span>Firebase Authentication</span><span class="state-text state-success">Verified Session</span></div>
          <div class="divider-row"><span>Cloud Firestore Database</span><span class="state-text ${appState.firestoreOk ? 'state-success' : 'state-danger'}">${appState.firestoreOk ? 'Connected' : 'Offline'}</span></div>
          <div class="divider-row"><span>Encrypted Biometric Vault</span><span class="state-text ${appState.health?.vault_ready ? 'state-success' : 'state-warning'}">${appState.health?.vault_ready ? 'AES-256-GCM Active' : 'Unavailable'}</span></div>
          <div class="divider-row"><span>AI Security Analyst (Gemini)</span><span class="state-text ${appState.health?.gemini_configured ? 'state-success' : 'state-warning'}">${appState.health?.gemini_configured ? 'Ready (Server-Side)' : 'Secret Not Configured'}</span></div>
          <div class="divider-row"><span>Feature Extraction Version</span><span class="mono">${escapeHtml(appState.health?.feature_version || 'v1.1-classical-liveness')}</span></div>
        </div>
      </section>
    </div>

    <form id="st-org-form" class="panel stack-md">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Threshold Presets &amp; Organization Policy</h2>
          <p class="panel-subtitle">${isAdmin ? 'Choose a quick sensitivity preset or adjust individual modality thresholds below.' : 'Administrator privileges are required to modify organization thresholds.'}</p>
        </div>
      </div>

      <div class="preset-grid" id="st-presets">
        ${THRESHOLD_PRESETS.map(
          (p) => `
          <button
            type="button"
            class="preset-btn ${activePresetId === p.id ? 'active' : ''}"
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
          <label class="field-label" for="st-org">Organization Name</label>
          <input class="input" id="st-org" ${isAdmin ? '' : 'disabled'} value="${escapeHtml(settings.organizationName)}" />
        </div>
        <div class="form-field">
          <label class="field-label" for="st-hold">Max Temporary Hold (Hours, 1–4)</label>
          <input class="input mono" id="st-hold" type="number" min="1" max="4" ${isAdmin ? '' : 'disabled'} value="${settings.maxHoldHours}" />
        </div>
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
      </div>
      ${isAdmin ? '<button type="submit" class="btn btn-primary" style="align-self:flex-start;">Save Organization Policy</button>' : ''}
    </form>
  `;

  container.querySelectorAll('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const preset = THRESHOLD_PRESETS.find((p) => p.id === btn.dataset.preset);
      if (!preset) return;
      container.querySelectorAll('[data-preset]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      container.querySelector('#st-f-thr').value = preset.faceThreshold;
      container.querySelector('#st-v-thr').value = preset.voiceThreshold;
      container.querySelector('#st-fp-thr').value = preset.fingerprintThreshold;
      container.querySelector('#st-3-thr').value = preset.threeModalThreshold;
      showToast(`Applied "${preset.label}" thresholds. Save to persist.`, 'neutral');
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

  container.querySelector('#st-org-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!isAdmin) return;
    const cfg = {
      organizationName: container.querySelector('#st-org').value.trim(),
      maxHoldHours: Number(container.querySelector('#st-hold').value),
      faceThreshold: Number(container.querySelector('#st-f-thr').value),
      voiceThreshold: Number(container.querySelector('#st-v-thr').value),
      fingerprintThreshold: Number(container.querySelector('#st-fp-thr').value),
      threeModalThreshold: Number(container.querySelector('#st-3-thr').value),
    };
    try {
      await saveSystemSettings(cfg);
      appState.settings = cfg;
      await appendAuditLog({
        action: 'system_settings_updated',
        resourceType: 'system_settings',
        resourceId: 'default',
        result: `Thresholds updated (F=${cfg.faceThreshold}, V=${cfg.voiceThreshold}, FP=${cfg.fingerprintThreshold})`,
      });
      showToast('Organization policy saved.', 'success');
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });

  container.querySelector('#st-refresh-health').addEventListener('click', async () => {
    try {
      appState.health = await fetchApiHealth();
      renderSettings(container, { appState, applyTheme });
      showToast('Diagnostics refreshed.', 'success');
    } catch (err) {
      showToast(err.message, 'danger');
    }
  });
}
