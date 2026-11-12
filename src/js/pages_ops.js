import {
  createSecurityAlert,
  updateSecurityAlert,
  createWorkflowDoc,
  updateWorkflowDoc,
  createApprovalRequest,
  reviewApprovalRequest,
  deleteIdentityMetadata,
  appendAuditLog,
  pushNotification,
} from './firebase.js';
import { deleteIdentityFromVault } from './api.js';
import { computeBiometricMetrics } from './biometrics.js';
import { drawRocChart, drawFarFrrChart } from './charts.js';
import { escapeHtml, fmtPct, showToast, openModal, downloadFile } from './ui.js';

function fmtFsTime(ts) {
  if (!ts) return '—';
  const d = typeof ts.toDate === 'function' ? ts.toDate() : new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function getRecommendedAction(alert) {
  const cat = String(alert.category || '').toLowerCase();
  if (cat.includes('spoof') || cat.includes('liveness')) {
    return 'Require live webcam motion + secondary voice/fingerprint check; inspect probe source for replay artifacts.';
  }
  if (alert.severity === 'critical' || alert.severity === 'high') {
    return 'Temporarily deactivate affected identity if unauthorized attempts persist; escalate in AI Security Analyst.';
  }
  return 'Correlate timestamps in Audit Logs and verify threshold preset alignment in Settings.';
}

// 5. ANALYTICS & SECURITY REPORTS
export function renderAnalytics(container, { appState }) {
  let daysFilter = 'all';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Analytics &amp; Security Reports</h1>
        <p class="page-subtitle">Operational telemetry, ROC/FAR-FRR curves, and exportable reports computed strictly from persisted Firestore records.</p>
      </div>
      <div class="page-actions">
        <div class="segmented" id="an-days">
          <button type="button" class="segmented-btn active" data-days="all">All Time</button>
          <button type="button" class="segmented-btn" data-days="7">Last 7d</button>
          <button type="button" class="segmented-btn" data-days="1">Last 24h</button>
        </div>
        <button type="button" class="btn btn-secondary" id="an-export-csv">Export CSV</button>
        <button type="button" class="btn btn-secondary" id="an-export-json">Export Security Report (JSON)</button>
      </div>
    </div>

    <div class="kpi-strip" id="an-kpis"></div>

    <div class="grid-2">
      <section class="panel stack-md" id="an-modalities"></section>
      <section class="panel stack-md" id="an-outcomes"></section>
    </div>

    <section class="panel stack-md" id="an-roc-panel"></section>
  `;

  const getFilteredVerifications = () => {
    const now = Date.now();
    const cutoff = daysFilter === 'all' ? 0 : now - Number(daysFilter) * 86400_000;
    return appState.verifications.filter((v) => {
      if (!cutoff) return true;
      const ms = typeof v.createdAt?.toMillis === 'function' ? v.createdAt.toMillis() : 0;
      return ms >= cutoff;
    });
  };

  const renderStats = () => {
    const verifications = getFilteredVerifications();
    const matches = verifications.filter((v) => v.outcome === 'match').length;
    const noMatches = verifications.filter((v) => v.outcome === 'no_match').length;

    const livenessKnown = verifications.filter((v) => typeof v.livenessPassed === 'boolean');
    const livenessPassed = livenessKnown.filter((v) => v.livenessPassed).length;
    const livenessPct = livenessKnown.length ? `${((livenessPassed / livenessKnown.length) * 100).toFixed(1)}%` : '—';

    const riskKnown = verifications.filter((v) => typeof v.riskScore === 'number');
    const avgRisk = riskKnown.length
      ? (riskKnown.reduce((s, v) => s + v.riskScore, 0) / riskKnown.length).toFixed(1)
      : '—';

    container.querySelector('#an-kpis').innerHTML = `
      <div class="kpi-cell">
        <span class="kpi-label">Total Identities</span>
        <span class="kpi-value">${appState.identities.length}</span>
        <span class="kpi-meta">${appState.identities.filter((i) => i.status === 'active').length} active enrolled</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Verification Requests</span>
        <span class="kpi-value">${verifications.length}</span>
        <span class="kpi-meta">${matches} match · ${noMatches} no-match</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Liveness Pass Rate</span>
        <span class="kpi-value">${livenessPct}</span>
        <span class="kpi-meta">${livenessKnown.length} check(s) with liveness data</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Average Risk Score</span>
        <span class="kpi-value">${avgRisk === '—' ? '—' : `${avgRisk} / 100`}</span>
        <span class="kpi-meta">${riskKnown.length} scored evaluation(s)</span>
      </div>
    `;

    const modCounts = { face: 0, voice: 0, fingerprint: 0 };
    for (const v of verifications) {
      for (const m of v.modalities || []) {
        if (m in modCounts) modCounts[m]++;
      }
    }
    const maxMod = Math.max(1, ...Object.values(modCounts));

    container.querySelector('#an-modalities').innerHTML = `
      <div class="panel-header">
        <div><h2 class="panel-title">Modality Usage</h2><p class="panel-subtitle">Modalities evaluated across persisted requests</p></div>
      </div>
      ${
        verifications.length === 0
          ? `<div class="empty-state"><div class="empty-title">Insufficient verification data</div><div class="empty-desc">Run biometric verification requests to populate real modality distribution metrics.</div></div>`
          : `<div class="stack-md">
              ${Object.entries(modCounts)
                .map(
                  ([mod, cnt]) => `
                <div class="stack-sm" style="gap:6px;">
                  <div class="row-between" style="font-size:13.5px;">
                    <strong style="text-transform:capitalize;">${mod}</strong>
                    <span class="mono">${cnt} evaluation(s)</span>
                  </div>
                  <div class="progress-track"><div class="progress-fill" style="width:${Math.round((cnt / maxMod) * 100)}%"></div></div>
                </div>`
                )
                .join('')}
            </div>`
      }
    `;

    container.querySelector('#an-outcomes').innerHTML = `
      <div class="panel-header">
        <div><h2 class="panel-title">Outcome &amp; Pipeline Breakdown</h2><p class="panel-subtitle">Actual Firestore verification_records summary</p></div>
      </div>
      ${
        verifications.length === 0
          ? `<div class="empty-state"><div class="empty-title">No records in selected window</div><div class="empty-desc">Adjust the time range filter or submit a verification request.</div></div>`
          : `<div class="table-wrap">
              <table class="data-table">
                <thead><tr><th>Identity</th><th>Pipeline</th><th>Outcome</th><th>Risk</th><th class="num-col">Score</th></tr></thead>
                <tbody>
                  ${verifications
                    .slice(0, 10)
                    .map(
                      (v) => `
                    <tr>
                      <td class="mono">${escapeHtml(v.identityRef)}</td>
                      <td class="mono">${escapeHtml(v.pipeline)}</td>
                      <td><span class="state-text ${v.outcome === 'match' ? 'state-success' : v.outcome === 'no_match' ? 'state-danger' : 'state-warning'}">${escapeHtml(v.outcome)}</span></td>
                      <td class="mono">${typeof v.riskScore === 'number' ? `${v.riskScore} (${escapeHtml(v.riskLevel || 'low')})` : '—'}</td>
                      <td class="num-col">${fmtPct(v.score || 0)}</td>
                    </tr>`
                    )
                    .join('')}
                </tbody>
              </table>
            </div>`
      }
    `;

    const rocPanel = container.querySelector('#an-roc-panel');
    const evaluated = verifications.filter((v) => v.outcome === 'match' || v.outcome === 'no_match');
    const hasMatch = evaluated.some((v) => v.outcome === 'match');
    const hasNoMatch = evaluated.some((v) => v.outcome === 'no_match');

    if (!hasMatch || !hasNoMatch) {
      rocPanel.innerHTML = `
        <div class="panel-header">
          <div><h2 class="panel-title">ROC &amp; FAR / FRR Operating Curves</h2><p class="panel-subtitle">Computed exclusively from persisted match and impostor/no-match records</p></div>
        </div>
        <div class="empty-state">
          <div class="empty-title">Need both match and no-match outcomes for ROC analysis</div>
          <div class="empty-desc">Run at least one matching verification and one impostor verification in Verification Center to plot real FAR, FRR, EER, and AUC curves.</div>
        </div>
      `;
    } else {
      const trials = evaluated.map((v) => ({
        score: Number(v.score || 0),
        genuine: v.outcome === 'match',
      }));
      const currentThr = Number(appState.settings?.faceThreshold ?? 0.72);
      const metrics = computeBiometricMetrics(trials, currentThr);
      rocPanel.innerHTML = `
        <div class="panel-header">
          <div>
            <h2 class="panel-title">ROC &amp; FAR / FRR Operating Curves</h2>
            <p class="panel-subtitle">Observed AUC ${(metrics.auc * 100).toFixed(1)}% · EER ${(metrics.eer * 100).toFixed(1)}% @ ${metrics.eerThreshold.toFixed(2)} across ${evaluated.length} persisted trial(s)</p>
          </div>
          <span class="meta-line">Current operating threshold: <strong class="mono">${currentThr.toFixed(2)}</strong></span>
        </div>
        <div class="grid-2">
          <div class="stack-sm">
            <span class="field-label">Receiver Operating Characteristic (ROC)</span>
            <canvas class="chart-canvas" id="an-roc-canvas" width="520" height="260"></canvas>
          </div>
          <div class="stack-sm">
            <span class="field-label">FAR vs FRR Across Threshold Sweep</span>
            <canvas class="chart-canvas" id="an-far-canvas" width="520" height="260"></canvas>
          </div>
        </div>
      `;
      drawRocChart(rocPanel.querySelector('#an-roc-canvas'), metrics.roc, currentThr, metrics.auc);
      drawFarFrrChart(rocPanel.querySelector('#an-far-canvas'), metrics.roc, currentThr, metrics.eerThreshold);
    }
  };

  renderStats();

  container.querySelectorAll('#an-days .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('#an-days .segmented-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      daysFilter = btn.dataset.days;
      renderStats();
    });
  });

  container.querySelector('#an-export-csv').addEventListener('click', () => {
    const header = 'verificationId,identityRef,pipeline,modalities,outcome,policyDecision,reasonCode,score,riskScore,riskLevel,livenessPassed,adaptiveApplied\n';
    const lines = appState.verifications
      .map((v) =>
        [
          v.verificationId,
          v.identityRef,
          v.pipeline,
          (v.modalities || []).join('+'),
          v.outcome,
          v.policyDecision,
          v.reasonCode,
          v.score,
          v.riskScore ?? '',
          v.riskLevel ?? '',
          v.livenessPassed ?? '',
          v.adaptiveApplied ?? '',
        ]
          .map((c) => `"${String(c ?? '').replaceAll('"', '""')}"`)
          .join(',')
      )
      .join('\n');
    downloadFile('bioguardx_verification_analytics.csv', header + lines);
    showToast('Exported analytics CSV.', 'success');
  });

  container.querySelector('#an-export-json').addEventListener('click', () => {
    const report = {
      generatedAt: new Date().toISOString(),
      organization: appState.settings?.organizationName || 'BioGuard X',
      summary: {
        enrolledIdentities: appState.identities.length,
        totalVerifications: appState.verifications.length,
        matches: appState.verifications.filter((v) => v.outcome === 'match').length,
        noMatches: appState.verifications.filter((v) => v.outcome === 'no_match').length,
        livenessFailures: appState.verifications.filter((v) => v.livenessPassed === false).length,
        highRiskEvents: appState.verifications.filter((v) => (v.riskScore ?? 0) >= 50).length,
        openAlerts: appState.alerts.filter((a) => a.status !== 'resolved').length,
        pendingApprovals: appState.approvals.filter((r) => r.status === 'pending').length,
      },
      verifications: appState.verifications,
      securityAlerts: appState.alerts,
      approvals: appState.approvals,
    };
    downloadFile('bioguardx_security_report.json', JSON.stringify(report, null, 2), 'application/json');
    showToast('Exported Security Report JSON.', 'success');
  });
}

// 6. RISK & THREAT ANALYSIS
export function renderThreatIntel(container, { appState, navigate }) {
  const canManage = appState.permissions.includes('manage_alerts');
  if (!canManage) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Risk &amp; Threat Analysis requires Security Analyst, Administrator, or Super Admin privileges.</div></div></div>`;
    return;
  }

  let sevFilter = 'all';
  let searchQ = '';

  const openAlertsCount = appState.alerts.filter((a) => a.status !== 'resolved').length;
  const highRiskVer = appState.verifications.filter((v) => (v.riskScore ?? 0) >= 50 || v.livenessPassed === false);
  const spoofFailures = appState.verifications.filter((v) => v.livenessPassed === false).length;
  const adaptiveTriggers = appState.verifications.filter((v) => v.adaptiveApplied === true).length;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Risk &amp; Threat Analysis</h1>
        <p class="page-subtitle">Investigate spoofing/liveness detections, suspicious verification velocity, and recommended security actions.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-primary" id="ti-new-alert">Create Security Alert</button>
      </div>
    </div>

    <div class="kpi-strip">
      <div class="kpi-cell">
        <span class="kpi-label">Open Security Alerts</span>
        <span class="kpi-value">${openAlertsCount}</span>
        <span class="kpi-meta">${appState.alerts.length} total alerts</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">High / Critical Risk Events</span>
        <span class="kpi-value">${appState.verifications.filter((v) => (v.riskScore ?? 0) >= 50).length}</span>
        <span class="kpi-meta">Risk score ≥ 50</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Spoof / Liveness Failures</span>
        <span class="kpi-value">${spoofFailures}</span>
        <span class="kpi-meta">Detected replay or flat texture</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Adaptive MFA Escalations</span>
        <span class="kpi-value">${adaptiveTriggers}</span>
        <span class="kpi-meta">Dynamic threshold / MFA checks</span>
      </div>
    </div>

    <section class="panel stack-md">
      <div class="row-between">
        <input type="search" class="input" id="ti-search" placeholder="Search alert category or description..." style="max-width:320px;" />
        <div class="segmented" id="ti-sev-tabs">
          <button type="button" class="segmented-btn active" data-sev="all">All</button>
          <button type="button" class="segmented-btn" data-sev="critical">Critical</button>
          <button type="button" class="segmented-btn" data-sev="high">High</button>
          <button type="button" class="segmented-btn" data-sev="medium">Medium</button>
          <button type="button" class="segmented-btn" data-sev="low">Low</button>
        </div>
      </div>

      <div id="ti-list" class="divider-list"></div>
    </section>

    <section class="panel stack-md">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">High-Risk &amp; Liveness-Flagged Attempts (${highRiskVer.length})</h2>
          <p class="panel-subtitle">Verification records flagged by liveness or behavioral risk scoring</p>
        </div>
      </div>
      ${
        highRiskVer.length === 0
          ? `<div class="empty-state"><div class="empty-title">No high-risk or liveness-flagged verification records</div><div class="empty-desc">Suspicious attempts and spoof rejections will appear here automatically.</div></div>`
          : `<div class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Identity Ref</th>
                    <th>Pipeline</th>
                    <th>Outcome</th>
                    <th>Liveness</th>
                    <th>Risk Score</th>
                    <th>Reason</th>
                    <th>Investigate</th>
                  </tr>
                </thead>
                <tbody>
                  ${highRiskVer
                    .slice(0, 15)
                    .map(
                      (v) => `
                    <tr>
                      <td class="mono"><strong>${escapeHtml(v.identityRef)}</strong></td>
                      <td class="mono">${escapeHtml(v.pipeline)}</td>
                      <td><span class="state-text ${v.outcome === 'match' ? 'state-success' : 'state-danger'}">${escapeHtml(v.outcome)}</span></td>
                      <td><span class="state-text ${v.livenessPassed === false ? 'state-danger' : 'state-success'}">${v.livenessPassed === false ? 'Failed' : 'Passed'}</span></td>
                      <td class="mono">${v.riskScore ?? '—'} (${escapeHtml(v.riskLevel || 'low')})</td>
                      <td class="mono" style="font-size:12px;">${escapeHtml(v.reasonCode)}</td>
                      <td><button type="button" class="btn btn-ghost btn-sm" data-ai-ver="${escapeHtml(v.verificationId)}">Explain in AI</button></td>
                    </tr>`
                    )
                    .join('')}
                </tbody>
              </table>
            </div>`
      }
    </section>
  `;

  container.querySelectorAll('[data-ai-ver]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const v = appState.verifications.find((x) => x.verificationId === btn.dataset.aiVer);
      if (!v) return;
      navigate('ai_analyst', {
        verificationId: v.verificationId,
        analystMode: 'explain_verification',
        analystPrompt: `Investigate flagged verification ${v.verificationId} for "${v.identityRef}" (${v.pipeline}, outcome=${v.outcome}, liveness=${v.livenessPassed}, risk=${v.riskScore}/100 ${v.riskLevel}, reason=${v.reasonCode}). What caused the flag and what next steps do you recommend?`,
      });
    });
  });

  const listEl = container.querySelector('#ti-list');

  const drawAlerts = () => {
    const filtered = appState.alerts.filter((a) => {
      if (sevFilter !== 'all' && a.severity !== sevFilter) return false;
      if (searchQ) {
        const q = searchQ.toLowerCase();
        return a.category.toLowerCase().includes(q) || a.description.toLowerCase().includes(q);
      }
      return true;
    });

    if (filtered.length === 0) {
      listEl.innerHTML = `<div class="empty-state"><div class="empty-title">No security alerts</div><div class="empty-desc">Create an investigation alert to track anomalies or suspicious biometric verification patterns.</div></div>`;
      return;
    }

    listEl.innerHTML = filtered
      .map((a) => {
        const sevCls = a.severity === 'critical' || a.severity === 'high' ? 'state-danger' : a.severity === 'medium' ? 'state-warning' : 'state-neutral';
        return `
        <div class="divider-row">
          <div class="stack-sm" style="gap:4px;flex:1;">
            <div class="meta-line">
              <span class="state-text ${sevCls}">${escapeHtml(a.severity.toUpperCase())}</span>
              <span aria-hidden="true">·</span>
              <strong>${escapeHtml(a.category)}</strong>
              <span aria-hidden="true">·</span>
              <span class="mono">status: ${escapeHtml(a.status)}</span>
              <span aria-hidden="true">·</span>
              <span class="mono">${escapeHtml(fmtFsTime(a.updatedAt))}</span>
            </div>
            <div style="font-size:14px;">${escapeHtml(a.description)}</div>
            <div style="font-size:12.5px;color:var(--accent);">Recommended action: ${escapeHtml(getRecommendedAction(a))}</div>
            ${a.notes ? `<div style="font-size:12.5px;color:var(--text-muted);">Notes: ${escapeHtml(a.notes)}</div>` : ''}
          </div>
          <div class="row-wrap">
            ${
              appState.permissions.includes('use_ai_analyst')
                ? `<button type="button" class="btn btn-ghost btn-sm" data-ai-alert="${escapeHtml(a.alertId)}">Investigate in AI</button>`
                : ''
            }
            <button type="button" class="btn btn-secondary btn-sm" data-edit-alert="${escapeHtml(a.alertId)}">Update</button>
          </div>
        </div>`;
      })
      .join('');

    listEl.querySelectorAll('[data-ai-alert]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const a = appState.alerts.find((x) => x.alertId === btn.dataset.aiAlert);
        if (!a) return;
        navigate('ai_analyst', {
          analystMode: 'investigate_activity',
          analystPrompt: `Investigate security alert ${a.alertId} (${a.severity.toUpperCase()} · ${a.category}): "${a.description}". Current status: ${a.status}. Analyze correlation with recent verifications and recommend remediation steps.`,
        });
      });
    });

    listEl.querySelectorAll('[data-edit-alert]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const alert = appState.alerts.find((x) => x.alertId === btn.dataset.editAlert);
        if (!alert) return;
        openModal({
          title: `Investigate Alert ${alert.alertId}`,
          bodyHtml: `
            <div class="stack-md">
              <div class="form-field">
                <label class="field-label" for="al-status">Status</label>
                <select class="select" id="al-status">
                  ${['open', 'investigating', 'resolved'].map((s) => `<option value="${s}" ${alert.status === s ? 'selected' : ''}>${s}</option>`).join('')}
                </select>
              </div>
              <div class="form-field">
                <label class="field-label" for="al-assigned">Assigned Analyst UID</label>
                <input class="input mono" id="al-assigned" value="${escapeHtml(alert.assignedTo || appState.fbUser.uid)}" />
              </div>
              <div class="form-field">
                <label class="field-label" for="al-notes">Investigation Notes</label>
                <textarea class="textarea" id="al-notes">${escapeHtml(alert.notes || '')}</textarea>
              </div>
            </div>
          `,
          footerButtons: [
            { label: 'Cancel', variant: 'btn-secondary' },
            {
              label: 'Save Update',
              variant: 'btn-primary',
              onClick: async ({ close, bodyEl }) => {
                try {
                  const status = bodyEl.querySelector('#al-status').value;
                  const assignedTo = bodyEl.querySelector('#al-assigned').value.trim();
                  const notes = bodyEl.querySelector('#al-notes').value.trim();
                  await updateSecurityAlert(alert.alertId, { status, assignedTo, notes });
                  await appendAuditLog({
                    action: 'security_alert_updated',
                    resourceType: 'security_alert',
                    resourceId: alert.alertId,
                    result: `Status=${status}`,
                  });
                  close();
                  showToast('Alert updated.', 'success');
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

  drawAlerts();

  container.querySelector('#ti-search').addEventListener('input', (e) => { searchQ = e.target.value; drawAlerts(); });
  container.querySelectorAll('#ti-sev-tabs .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('#ti-sev-tabs .segmented-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      sevFilter = btn.dataset.sev;
      drawAlerts();
    });
  });

  container.querySelector('#ti-new-alert').addEventListener('click', () => {
    openModal({
      title: 'Create Security Alert',
      bodyHtml: `
        <div class="stack-md">
          <div class="form-field">
            <label class="field-label" for="na-sev">Severity</label>
            <select class="select" id="na-sev">
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
              <option value="low">low</option>
            </select>
          </div>
          <div class="form-field">
            <label class="field-label" for="na-cat">Category</label>
            <input class="input" id="na-cat" required placeholder="Repeated Verification Failure" />
          </div>
          <div class="form-field">
            <label class="field-label" for="na-desc">Description</label>
            <textarea class="textarea" id="na-desc" required placeholder="Document observed evidence and affected identity references..."></textarea>
          </div>
        </div>
      `,
      footerButtons: [
        { label: 'Cancel', variant: 'btn-secondary' },
        {
          label: 'Create Alert',
          variant: 'btn-primary',
          onClick: async ({ close, bodyEl }) => {
            const severity = bodyEl.querySelector('#na-sev').value;
            const category = bodyEl.querySelector('#na-cat').value.trim();
            const description = bodyEl.querySelector('#na-desc').value.trim();
            if (!category || !description) { showToast('Category and description are required.', 'warning'); return; }
            try {
              const id = await createSecurityAlert({ severity, category, description, assignedTo: appState.fbUser.uid });
              await appendAuditLog({ action: 'security_alert_created', resourceType: 'security_alert', resourceId: id, result: `${severity}: ${category}` });
              close();
              showToast('Security alert created.', 'success');
            } catch (err) {
              showToast(err.message, 'danger');
            }
          },
        },
      ],
    });
  });
}

// 7. APPROVAL WORKFLOW
export function renderApprovals(container, { appState }) {
  const canApprove = appState.permissions.includes('manage_approvals');
  const pendingCount = appState.approvals.filter((r) => r.status === 'pending').length;

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Approval Workflow</h1>
        <p class="page-subtitle">Controlled two-step authorization for sensitive biometric deletion and policy review requests.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-primary" id="ap-new-btn">New Approval Request</button>
      </div>
    </div>

    <div class="kpi-strip">
      <div class="kpi-cell">
        <span class="kpi-label">Pending Requests</span>
        <span class="kpi-value">${pendingCount}</span>
        <span class="kpi-meta">Awaiting administrator sign-off</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Approved</span>
        <span class="kpi-value">${appState.approvals.filter((r) => r.status === 'approved').length}</span>
        <span class="kpi-meta">Executed &amp; audited</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Rejected</span>
        <span class="kpi-value">${appState.approvals.filter((r) => r.status === 'rejected').length}</span>
        <span class="kpi-meta">Declined with review notes</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Review Authority</span>
        <span class="kpi-value" style="font-size:20px;">${canApprove ? 'Authorized' : 'Requester'}</span>
        <span class="kpi-meta">Role: ${escapeHtml(appState.profile?.role || 'viewer')}</span>
      </div>
    </div>

    <section class="panel stack-md">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Approval Queue (${appState.approvals.length})</h2>
          <p class="panel-subtitle">${canApprove ? 'Approving a biometric_deletion request purges the encrypted vault template and Firestore metadata.' : 'Showing approval requests submitted by your account.'}</p>
        </div>
      </div>

      ${
        appState.approvals.length === 0
          ? `<div class="empty-state"><div class="empty-title">No approval requests yet</div><div class="empty-desc">Submit a controlled deletion or policy review request from here or the Identities directory.</div></div>`
          : `<div class="divider-list" id="ap-list">
              ${appState.approvals
                .map((r) => {
                  const stCls = r.status === 'approved' ? 'state-success' : r.status === 'rejected' ? 'state-danger' : 'state-warning';
                  return `
                  <div class="divider-row">
                    <div class="stack-sm" style="gap:4px;flex:1;">
                      <div class="meta-line">
                        <span class="state-text ${stCls}">${escapeHtml(r.status.toUpperCase())}</span>
                        <span aria-hidden="true">·</span>
                        <strong class="mono">${escapeHtml(r.requestType)}</strong>
                        <span aria-hidden="true">·</span>
                        <span>Target: <strong class="mono">${escapeHtml(r.targetIdentityRef)}</strong></span>
                        <span aria-hidden="true">·</span>
                        <span class="mono">${escapeHtml(fmtFsTime(r.updatedAt))}</span>
                      </div>
                      <div style="font-size:14px;">${escapeHtml(r.reason)}</div>
                      <div class="meta-line">Requested by: <span class="mono">${escapeHtml(r.requestedByEmail || r.requestedBy)}</span></div>
                      ${r.reviewNotes ? `<div style="font-size:12.5px;color:var(--text-muted);">Review notes: ${escapeHtml(r.reviewNotes)}</div>` : ''}
                    </div>
                    ${
                      canApprove && r.status === 'pending'
                        ? `<div class="row-wrap">
                            <button type="button" class="btn btn-primary btn-sm" data-ap-act="approved" data-ap-id="${escapeHtml(r.requestId)}">Approve</button>
                            <button type="button" class="btn btn-danger btn-sm" data-ap-act="rejected" data-ap-id="${escapeHtml(r.requestId)}">Reject</button>
                          </div>`
                        : ''
                    }
                  </div>`;
                })
                .join('')}
            </div>`
      }
    </section>
  `;

  container.querySelector('#ap-new-btn').addEventListener('click', () => {
    if (appState.identities.length === 0) {
      showToast('Enroll an identity first before creating an identity approval request.', 'warning');
      return;
    }
    openModal({
      title: 'Submit Approval Request',
      bodyHtml: `
        <div class="stack-md">
          <div class="form-field">
            <label class="field-label" for="ap-type">Request Type</label>
            <select class="select mono" id="ap-type">
              <option value="biometric_deletion">biometric_deletion</option>
              <option value="policy_override_review">policy_override_review</option>
            </select>
          </div>
          <div class="form-field">
            <label class="field-label" for="ap-target">Target Identity</label>
            <select class="select" id="ap-target">
              ${appState.identities.map((i) => `<option value="${escapeHtml(i.identityRef)}">${escapeHtml(i.displayName)} (${escapeHtml(i.identityRef)})</option>`).join('')}
            </select>
          </div>
          <div class="form-field">
            <label class="field-label" for="ap-reason">Justification</label>
            <textarea class="textarea" id="ap-reason" placeholder="Document policy or consent justification..."></textarea>
          </div>
        </div>
      `,
      footerButtons: [
        { label: 'Cancel', variant: 'btn-secondary' },
        {
          label: 'Submit Request',
          variant: 'btn-primary',
          onClick: async ({ close, bodyEl }) => {
            const requestType = bodyEl.querySelector('#ap-type').value;
            const targetIdentityRef = bodyEl.querySelector('#ap-target').value;
            const reason = bodyEl.querySelector('#ap-reason').value.trim();
            if (reason.length < 5) {
              showToast('Provide a justification of at least 5 characters.', 'warning');
              return;
            }
            try {
              const id = await createApprovalRequest({ requestType, targetIdentityRef, reason });
              await appendAuditLog({
                action: 'approval_requested',
                resourceType: 'approval_request',
                resourceId: id,
                result: `${requestType} for ${targetIdentityRef}`,
              });
              close();
              showToast(`Approval request "${id}" created.`, 'success');
            } catch (err) {
              showToast(err.message, 'danger');
            }
          },
        },
      ],
    });
  });

  container.querySelectorAll('[data-ap-act]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const requestId = btn.dataset.apId;
      const decision = btn.dataset.apAct;
      const req = appState.approvals.find((r) => r.requestId === requestId);
      if (!req) return;

      openModal({
        title: `${decision === 'approved' ? 'Approve' : 'Reject'} Request ${requestId}`,
        bodyHtml: `
          <div class="stack-md">
            <p style="font-size:13.5px;color:var(--text-secondary);">
              Type: <strong class="mono">${escapeHtml(req.requestType)}</strong> · Target: <strong class="mono">${escapeHtml(req.targetIdentityRef)}</strong>
              ${decision === 'approved' && req.requestType === 'biometric_deletion' ? '<br/><span class="state-danger">Approving will permanently delete the encrypted template and identity record.</span>' : ''}
            </p>
            <div class="form-field">
              <label class="field-label" for="ap-notes">Review Notes</label>
              <textarea class="textarea" id="ap-notes" placeholder="Optional compliance or verification remarks..."></textarea>
            </div>
          </div>
        `,
        footerButtons: [
          { label: 'Cancel', variant: 'btn-secondary' },
          {
            label: decision === 'approved' ? 'Confirm Approval' : 'Confirm Rejection',
            variant: decision === 'approved' ? 'btn-primary' : 'btn-danger',
            onClick: async ({ close, bodyEl }) => {
              const reviewNotes = bodyEl.querySelector('#ap-notes').value.trim();
              try {
                if (decision === 'approved' && req.requestType === 'biometric_deletion') {
                  await deleteIdentityFromVault(req.targetIdentityRef).catch(() => null);
                  await deleteIdentityMetadata(req.targetIdentityRef).catch(() => null);
                }
                await reviewApprovalRequest(requestId, { status: decision, reviewNotes });
                await appendAuditLog({
                  action: `approval_${decision}`,
                  resourceType: 'approval_request',
                  resourceId: requestId,
                  result: `${req.requestType} on ${req.targetIdentityRef} -> ${decision}`,
                });
                await pushNotification({
                  title: `Approval Request ${decision === 'approved' ? 'Approved' : 'Rejected'}`,
                  message: `${req.requestType} for "${req.targetIdentityRef}" was ${decision}.`,
                  type: decision === 'approved' ? 'success' : 'warning',
                  targetUid: req.requestedBy,
                }).catch(() => null);
                close();
                showToast(`Request ${decision}.`, 'success');
              } catch (err) {
                showToast(err.message, 'danger');
              }
            },
          },
        ],
      });
    });
  });
}

// 8. AUTOMATION CENTER
export function renderAutomationCenter(container, { appState }) {
  const canManage = appState.permissions.includes('manage_workflows');
  const isAnalystOrAbove = ['super_admin', 'administrator', 'security_analyst'].includes(appState.profile?.role);
  if (!isAnalystOrAbove) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Automation Center requires Security Analyst, Administrator, or Super Admin privileges.</div></div></div>`;
    return;
  }

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Automation Center</h1>
        <p class="page-subtitle">Configure authorized event-driven workflows in Cloud Firestore. Automatic physical access decisions are prohibited.</p>
      </div>
      <div class="page-actions">
        ${canManage ? `<button type="button" class="btn btn-primary" id="ac-new-wf">Create Workflow</button>` : ''}
      </div>
    </div>

    <section class="panel stack-md">
      <div class="panel-header">
        <div><h2 class="panel-title">Persisted Workflows (${appState.workflows.length})</h2><p class="panel-subtitle">Changes are audited and enforced via Firestore rules</p></div>
      </div>

      ${
        appState.workflows.length === 0
          ? `<div class="empty-state"><div class="empty-title">No automation workflows defined</div><div class="empty-desc">${canManage ? 'Create an authorized workflow to monitor security alerts or report generation.' : 'Contact an Administrator to configure automation workflows.'}</div></div>`
          : `<div class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Workflow</th>
                    <th>Trigger</th>
                    <th>Permitted Actions</th>
                    <th>State</th>
                    <th>Controls</th>
                  </tr>
                </thead>
                <tbody>
                  ${appState.workflows
                    .map(
                      (wf) => `
                    <tr>
                      <td>
                        <strong>${escapeHtml(wf.name)}</strong>
                        <div style="font-size:12px;color:var(--text-muted);">${escapeHtml(wf.description || wf.workflowId)}</div>
                      </td>
                      <td class="mono">${escapeHtml(wf.trigger)}</td>
                      <td class="mono">${escapeHtml((wf.actions || []).join(', '))}</td>
                      <td><span class="state-text ${wf.enabled ? 'state-success' : 'state-neutral'}">${wf.enabled ? 'Enabled' : 'Disabled'}</span></td>
                      <td>
                        ${
                          canManage
                            ? `<button type="button" class="btn btn-secondary btn-sm" data-toggle-wf="${escapeHtml(wf.workflowId)}" data-next-en="${!wf.enabled}">${wf.enabled ? 'Disable' : 'Enable'}</button>`
                            : '<span class="meta-line">Read-only</span>'
                        }
                      </td>
                    </tr>`
                    )
                    .join('')}
                </tbody>
              </table>
            </div>`
      }
    </section>
  `;

  container.querySelectorAll('[data-toggle-wf]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.toggleWf;
      const enabled = btn.dataset.nextEn === 'true';
      try {
        await updateWorkflowDoc(id, { enabled });
        await appendAuditLog({ action: 'workflow_toggled', resourceType: 'workflow', resourceId: id, result: `enabled=${enabled}` });
        showToast(`Workflow ${enabled ? 'enabled' : 'disabled'}.`, 'success');
      } catch (err) {
        showToast(err.message, 'danger');
      }
    });
  });

  container.querySelector('#ac-new-wf')?.addEventListener('click', () => {
    openModal({
      title: 'Create Automation Workflow',
      bodyHtml: `
        <div class="stack-md">
          <div class="form-field">
            <label class="field-label" for="wf-name">Workflow Name</label>
            <input class="input" id="wf-name" required placeholder="High-Severity Alert Escalation" />
          </div>
          <div class="form-field">
            <label class="field-label" for="wf-desc">Description</label>
            <input class="input" id="wf-desc" placeholder="Notify analysts when repeated verification failures occur" />
          </div>
          <div class="form-field">
            <label class="field-label" for="wf-trig">Trigger Event</label>
            <select class="select mono" id="wf-trig">
              <option value="repeated_no_match">repeated_no_match</option>
              <option value="security_alert_created">security_alert_created</option>
              <option value="identity_enrolled">identity_enrolled</option>
              <option value="scheduled_digest">scheduled_digest</option>
            </select>
          </div>
          <div class="form-field">
            <label class="field-label" for="wf-act">Permitted Action</label>
            <select class="select mono" id="wf-act">
              <option value="create_security_alert">create_security_alert</option>
              <option value="send_operator_notification">send_operator_notification</option>
              <option value="compile_audit_digest">compile_audit_digest</option>
            </select>
          </div>
        </div>
      `,
      footerButtons: [
        { label: 'Cancel', variant: 'btn-secondary' },
        {
          label: 'Create Workflow',
          variant: 'btn-primary',
          onClick: async ({ close, bodyEl }) => {
            const name = bodyEl.querySelector('#wf-name').value.trim();
            const description = bodyEl.querySelector('#wf-desc').value.trim();
            const trigger = bodyEl.querySelector('#wf-trig').value;
            const action = bodyEl.querySelector('#wf-act').value;
            if (!name) { showToast('Workflow name is required.', 'warning'); return; }
            try {
              const id = await createWorkflowDoc({ name, description, trigger, actions: [action] });
              await appendAuditLog({ action: 'workflow_created', resourceType: 'workflow', resourceId: id, result: `${name} (${trigger})` });
              close();
              showToast('Workflow saved to Firestore.', 'success');
            } catch (err) {
              showToast(err.message, 'danger');
            }
          },
        },
      ],
    });
  });
}

// 9. AUDIT LOGS
export function renderAuditTrail(container, { appState }) {
  let q = '';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Audit Logs</h1>
        <p class="page-subtitle">Immutable Cloud Firestore audit records without raw biometric samples, encryption keys, or tokens.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-secondary" id="at-csv">Export CSV</button>
        <button type="button" class="btn btn-secondary" id="at-json">Export JSON</button>
      </div>
    </div>

    <section class="panel stack-md">
      <div class="row-between">
        <input type="search" class="input" id="at-search" placeholder="Filter by action, actor UID, resource, or request ID..." style="max-width:380px;" />
        <span id="at-count" class="meta-line"></span>
      </div>

      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Actor UID</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Result</th>
              <th>Request ID</th>
            </tr>
          </thead>
          <tbody id="at-tbody"></tbody>
        </table>
      </div>
    </section>
  `;

  const tbody = container.querySelector('#at-tbody');
  const countEl = container.querySelector('#at-count');

  const drawLogs = () => {
    const term = q.trim().toLowerCase();
    const rows = appState.auditLogs.filter(
      (l) =>
        !term ||
        l.action.toLowerCase().includes(term) ||
        l.actorUid.toLowerCase().includes(term) ||
        l.resourceId.toLowerCase().includes(term) ||
        l.result.toLowerCase().includes(term) ||
        l.requestId.toLowerCase().includes(term)
    );
    countEl.textContent = `${rows.length} audit event(s)`;
    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--text-muted);">No matching audit records.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows
      .slice(0, 120)
      .map(
        (l) => `
      <tr>
        <td class="mono" style="font-size:12px;white-space:nowrap;">${escapeHtml(fmtFsTime(l.timestamp))}</td>
        <td class="mono" style="font-size:12px;">${escapeHtml(l.actorUid.slice(0, 12))}...</td>
        <td class="mono">${escapeHtml(l.action)}</td>
        <td class="mono">${escapeHtml(l.resourceType)}:${escapeHtml(l.resourceId)}</td>
        <td>${escapeHtml(l.result)}</td>
        <td class="mono" style="font-size:12px;">${escapeHtml(l.requestId)}</td>
      </tr>`
      )
      .join('');
  };

  drawLogs();
  container.querySelector('#at-search').addEventListener('input', (e) => { q = e.target.value; drawLogs(); });

  container.querySelector('#at-csv').addEventListener('click', () => {
    const header = 'eventId,actorUid,action,resourceType,resourceId,result,requestId\n';
    const lines = appState.auditLogs
      .map((l) => [l.eventId, l.actorUid, l.action, l.resourceType, l.resourceId, l.result, l.requestId].map((c) => `"${String(c).replaceAll('"', '""')}"`).join(','))
      .join('\n');
    downloadFile('bioguardx_audit_trail.csv', header + lines);
    showToast('Audit CSV exported.', 'success');
  });

  container.querySelector('#at-json').addEventListener('click', () => {
    downloadFile('bioguardx_audit_trail.json', JSON.stringify(appState.auditLogs, null, 2), 'application/json');
    showToast('Audit JSON exported.', 'success');
  });
}
