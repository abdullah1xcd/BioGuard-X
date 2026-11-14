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
  getFirestoreTelemetry,
} from './firebase.js';
import { deleteIdentityFromVault } from './api.js';
import { buildBiometricAnalyticsReport } from './biometrics.js';
import {
  drawRocChart,
  drawFarFrrChart,
  drawVerificationTrendChart,
  drawModalityComparisonChart,
  observeResponsiveChart,
} from './charts.js';
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
  let scopeFilter = 'all'; // 'all' | 'labeled' | 'operational'
  let customStart = '';
  let customEnd = '';

  container.innerHTML = `
    <div class="page-header">
      <div>
        <h1 class="page-title">Analytics &amp; Reports</h1>
        <p class="page-subtitle">Measured classification accuracy, operational verification rates, and ROC analysis from persisted Firestore records.</p>
      </div>
      <div class="page-actions">
        <button type="button" class="btn btn-secondary" id="an-export-csv">Export CSV</button>
        <button type="button" class="btn btn-secondary" id="an-export-json">Export Report (JSON)</button>
      </div>
    </div>

    <section class="panel stack-sm">
      <div class="row-between">
        <div class="segmented" id="an-days">
          <button type="button" class="segmented-btn active" data-days="all">All Time</button>
          <button type="button" class="segmented-btn" data-days="90">90d</button>
          <button type="button" class="segmented-btn" data-days="30">30d</button>
          <button type="button" class="segmented-btn" data-days="7">7d</button>
          <button type="button" class="segmented-btn" data-days="1">Today</button>
          <button type="button" class="segmented-btn" data-days="custom">Custom</button>
        </div>
        <div class="segmented" id="an-scope">
          <button type="button" class="segmented-btn active" data-scope="all">All Records</button>
          <button type="button" class="segmented-btn" data-scope="labeled">Labeled Trials Only</button>
          <button type="button" class="segmented-btn" data-scope="operational">Operational Only</button>
        </div>
      </div>
      <div id="an-custom-dates" class="row-wrap" hidden style="padding-top:6px;">
        <label class="meta-line">From <input type="date" class="input" id="an-start" style="width:auto;min-height:34px;" /></label>
        <label class="meta-line">To <input type="date" class="input" id="an-end" style="width:auto;min-height:34px;" /></label>
        <button type="button" class="btn btn-secondary btn-sm" id="an-apply-custom">Apply Range</button>
      </div>
    </section>

    <details class="advanced-details">
      <summary>Methodology &amp; Statistical Integrity Definitions</summary>
      <div class="advanced-details-body" style="font-size:12.5px;color:var(--text-secondary);">
        <div><strong>1. Model Similarity:</strong> Normalized biometric feature closeness (not an identity probability).</div>
        <div><strong>2. Verification Confidence:</strong> Composite index from threshold margin, signal quality, liveness checks, and modality agreement.</div>
        <div><strong>3. Classification Accuracy (TAR/FAR/FRR/EER/F1):</strong> Computed exclusively from ground-truth labeled Genuine vs. Impostor trials using subject-disjoint evaluation methodology.</div>
        <div><strong>4. Operational Success Rate:</strong> Fraction of live operational attempts resulting in a match.</div>
      </div>
    </details>

    <div class="kpi-strip" id="an-kpis"></div>

    <section class="panel stack-md" id="an-datasets-panel"></section>

    <section class="panel stack-md" id="an-classification-panel"></section>

    <div class="grid-2">
      <section class="panel stack-md" id="an-trends-panel"></section>
      <section class="panel stack-md" id="an-modcomp-panel"></section>
    </div>

    <section class="panel stack-md" id="an-roc-panel"></section>

    <div class="grid-2">
      <section class="panel stack-md" id="an-modalities"></section>
      <section class="panel stack-md" id="an-latency-panel"></section>
    </div>
  `;

  const getFilteredVerifications = () => {
    const now = Date.now();
    return appState.verifications.filter((v) => {
      const ms = typeof v.createdAt?.toMillis === 'function' ? v.createdAt.toMillis() : 0;
      if (daysFilter === 'custom') {
        const sMs = customStart ? Date.parse(`${customStart}T00:00:00`) : 0;
        const eMs = customEnd ? Date.parse(`${customEnd}T23:59:59`) : Number.MAX_SAFE_INTEGER;
        if (sMs && ms < sMs) return false;
        if (eMs && ms > eMs) return false;
      } else if (daysFilter !== 'all') {
        const cutoff = now - Number(daysFilter) * 86400_000;
        if (ms < cutoff) return false;
      }
      if (scopeFilter === 'labeled') {
        return v.groundTruth === 'genuine' || v.groundTruth === 'impostor';
      }
      if (scopeFilter === 'operational') {
        return !v.isTestProbe;
      }
      return true;
    });
  };

  let latestReport = null;
  let chartCleanups = [];
  const clearCharts = () => {
    chartCleanups.forEach((fn) => fn());
    chartCleanups = [];
  };

  const renderStats = () => {
    clearCharts();
    const verifications = getFilteredVerifications();
    const s = appState.settings || {};
    const activeCount = appState.identities.filter((i) => i.status === 'active').length;
    const report = buildBiometricAnalyticsReport(verifications, appState.identities.length, activeCount, {
      face: s.faceThreshold ?? 0.72,
      voice: s.voiceThreshold ?? 0.70,
      fingerprint: s.fingerprintThreshold ?? 0.72,
      threeModal: s.threeModalThreshold ?? 0.74,
    });
    latestReport = report;

    const dsOp = report.datasets.operational;
    const dsQa = report.datasets.syntheticQa;
    const dsBm = report.datasets.benchmark;

    const livenessPct = report.livenessKnownCount ? fmtPct(report.livenessSuccessRate) : '—';
    const opPct = dsOp.operationalMatchRate !== null ? fmtPct(dsOp.operationalMatchRate) : '—';
    const capFailPct = dsOp.captureFailureRate !== null ? fmtPct(dsOp.captureFailureRate) : '—';
    const incPct = report.totalAttempts > 0 ? fmtPct(report.inconclusiveRate) : '—';
    const liveFailPct = report.livenessKnownCount ? fmtPct(report.livenessFailureRate) : '—';
    const qDist = report.sampleQualityDistribution;

    container.querySelector('#an-kpis').innerHTML = `
      <div class="kpi-cell">
        <span class="kpi-label">Registered Identities</span>
        <span class="kpi-value">${report.totalIdentities}</span>
        <span class="kpi-meta">${report.activeIdentities} active · ${report.totalAttempts} record(s) in range</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Verified / Rejected / Inc.</span>
        <span class="kpi-value">${report.successfulVerifications} / ${report.rejectedVerifications} / ${report.notEvaluatedVerifications}</span>
        <span class="kpi-meta">Inconclusive ${incPct} · Capture fail ${capFailPct}</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Operational Match Rate</span>
        <span class="kpi-value">${opPct}</span>
        <span class="kpi-meta">${dsOp.totalAttempts} real ops · ${dsQa.totalProbes} QA probe(s)</span>
      </div>
      <div class="kpi-cell">
        <span class="kpi-label">Confirmed Liveness Pass / Fail</span>
        <span class="kpi-value">${livenessPct} <span style="font-size:14px;color:var(--text-muted);">/ ${liveFailPct}</span></span>
        <span class="kpi-meta">${report.livenessKnownCount} live/spoof check(s) · ${report.conflictCount} conflict(s)</span>
      </div>
    `;

    container.querySelector('#an-datasets-panel').innerHTML = `
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Dataset Provenance &amp; Strict Isolation</h2>
          <p class="panel-subtitle">Real Operational traffic, Synthetic QA probes, and Benchmark Labeled trials are isolated — never blended into fake accuracy claims</p>
        </div>
      </div>
      <div class="analytics-dataset-grid">
        <div class="dataset-card">
          <div class="row-between">
            <strong>1. Real Operational Data</strong>
            <span class="state-text state-success">${dsOp.totalAttempts} attempt(s)</span>
          </div>
          <div class="divider-list" style="font-size:12.5px;">
            <div class="divider-row"><span>Verified / Rejected / Inconclusive</span><span class="mono">${dsOp.verifiedCount} / ${dsOp.rejectedCount} / ${dsOp.inconclusiveCount}</span></div>
            <div class="divider-row"><span>Operational Match Rate</span><span class="mono">${opPct}</span></div>
            <div class="divider-row"><span>Capture Failures / Rate</span><span class="mono">${dsOp.captureFailureCount} (${capFailPct})</span></div>
            <div class="divider-row"><span>Liveness Pass / Fail / Inc. / NS</span><span class="mono">${dsOp.livenessPassedCount} / ${dsOp.livenessFailedCount} / ${dsOp.livenessInconclusiveCount} / ${dsOp.livenessNotSupportedCount}</span></div>
          </div>
        </div>

        <div class="dataset-card">
          <div class="row-between">
            <strong>2. Synthetic QA / Testing Data</strong>
            <span class="state-text state-warning">${dsQa.totalProbes} probe(s)</span>
          </div>
          <div class="divider-list" style="font-size:12.5px;">
            <div class="divider-row"><span>Verified / Rejected / Inconclusive</span><span class="mono">${dsQa.verifiedCount} / ${dsQa.rejectedCount} / ${dsQa.inconclusiveCount}</span></div>
            <div class="divider-row"><span>Genuine / Impostor QA Labels</span><span class="mono">${dsQa.genuineProbes} / ${dsQa.impostorProbes}</span></div>
            <div class="divider-row"><span>Sample Quality (Good / Bord / Poor)</span><span class="mono">${qDist.goodCount} / ${qDist.borderlineCount} / ${qDist.poorCount}${qDist.meanQuality !== null ? ` (μ=${qDist.meanQuality})` : ''}</span></div>
            <div class="divider-row"><span>Operational Contamination</span><span class="state-text state-success">Excluded (0%)</span></div>
          </div>
        </div>

        <div class="dataset-card">
          <div class="row-between">
            <strong>3. Labeled Benchmark Evaluation</strong>
            <span class="state-text ${dsBm.insufficientData ? 'state-warning' : 'state-success'}">${dsBm.totalLabeledTrials} trial(s)</span>
          </div>
          <div class="divider-list" style="font-size:12.5px;">
            <div class="divider-row"><span>Operational vs Synthetic Labeled</span><span class="mono">${dsBm.operationalLabeledTrials} ops · ${dsBm.syntheticLabeledTrials} synth</span></div>
            <div class="divider-row"><span>Genuine / Impostor Counts</span><span class="mono">${dsBm.classification.genuineCount} / ${dsBm.classification.impostorCount}</span></div>
            <div class="divider-row"><span>Liveness (Pass / Fail / Inc / NS)</span><span class="mono">${report.livenessBreakdown.passed} / ${report.livenessBreakdown.failed} / ${report.livenessBreakdown.inconclusive} / ${report.livenessBreakdown.notSupported}</span></div>
            <div class="divider-row"><span>Statistical Readiness</span><span class="state-text ${dsBm.insufficientData ? 'state-warning' : 'state-success'}">${dsBm.insufficientData ? 'Insufficient validated data' : 'Ready (≥3 per class)'}</span></div>
          </div>
        </div>
      </div>
    `;

    const c = report.classification;
    const drStart = report.dateRange.startMs ? new Date(report.dateRange.startMs).toLocaleDateString() : '—';
    const drEnd = report.dateRange.endMs ? new Date(report.dateRange.endMs).toLocaleDateString() : '—';
    const ciText = (ci) => (c.sampleCount > 0 ? `CI [${(ci.low * 100).toFixed(1)}%–${(ci.high * 100).toFixed(1)}%]` : '—');

    container.querySelector('#an-classification-panel').innerHTML = `
      <div class="panel-header">
        <div>
          <h2 class="panel-title">Measured Classification Accuracy (Benchmark Labeled Trials)</h2>
          <p class="panel-subtitle">Sample size: ${c.sampleCount} labeled (${c.genuineCount} genuine, ${c.impostorCount} impostor) · ${report.unlabeledAttempts} unlabeled excluded · Range: ${escapeHtml(drStart)} → ${escapeHtml(drEnd)}</p>
        </div>
        <span class="state-text ${c.insufficientData ? 'state-warning' : 'state-success'}">${c.insufficientData ? 'Insufficient validated data' : 'Statistically Grounded'}</span>
      </div>

      ${
        c.insufficientData
          ? `<div class="notice-strip warning"><div><strong>${escapeHtml(dsBm.insufficientDataMessage || 'Insufficient validated data')}</strong><div>${escapeHtml(c.insufficientReason)} Run at least 3 Genuine and 3 Impostor labeled evaluation trials to report statistically valid FAR, FRR, and EER bounds.</div></div></div>`
          : ''
      }

      ${
        c.sampleCount > 0
          ? `
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Metric</th>
                <th class="num-col">Value</th>
                <th>95% Wilson CI</th>
                <th>Formula / Meaning</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Overall Accuracy</strong></td>
                <td class="num-col">${fmtPct(c.accuracy)}</td>
                <td class="mono" style="font-size:12px;">${ciText(c.ci95.accuracy)}</td>
                <td class="meta-line">(TP + TN) / Total (${c.tp} TP, ${c.tn} TN, ${c.fp} FP, ${c.fn} FN)</td>
              </tr>
              <tr>
                <td><strong>TAR / GAR / Recall</strong></td>
                <td class="num-col">${fmtPct(c.tar)}</td>
                <td class="mono" style="font-size:12px;">${ciText(c.ci95.tar)}</td>
                <td class="meta-line">TP / (TP + FN) — Genuine Acceptance Rate (1 − FRR)</td>
              </tr>
              <tr>
                <td><strong>FAR / IAR</strong></td>
                <td class="num-col">${fmtPct(c.far)}</td>
                <td class="mono" style="font-size:12px;">${ciText(c.ci95.far)}</td>
                <td class="meta-line">FP / (FP + TN) — Impostor Acceptance Rate</td>
              </tr>
              <tr>
                <td><strong>FRR</strong></td>
                <td class="num-col">${fmtPct(c.frr)}</td>
                <td class="mono" style="font-size:12px;">${ciText(c.ci95.frr)}</td>
                <td class="meta-line">FN / (TP + FN) — False Rejection Rate</td>
              </tr>
              <tr>
                <td><strong>Precision &amp; F1 Score</strong></td>
                <td class="num-col">${fmtPct(c.precision)} / ${fmtPct(c.f1)}</td>
                <td class="mono" style="font-size:12px;">—</td>
                <td class="meta-line">Precision = TP/(TP+FP) · F1 = harmonic mean(P, R)</td>
              </tr>
              <tr>
                <td><strong>EER &amp; ROC AUC</strong></td>
                <td class="num-col">${c.roc.length ? `${fmtPct(c.eer)} @ ${c.eerThreshold.toFixed(2)}` : '—'} · AUC ${c.roc.length ? c.auc.toFixed(3) : '—'}</td>
                <td class="mono" style="font-size:12px;">Threshold sweep</td>
                <td class="meta-line">Equal Error Rate where FAR ≈ FRR; requires both genuine &amp; impostor labels</td>
              </tr>
            </tbody>
          </table>
        </div>`
          : `<div class="empty-state"><div class="empty-title">Insufficient validated data</div><div class="empty-desc">Operational traffic remains excluded from accuracy claims unless explicitly labeled as genuine or impostor.</div></div>`
      }
    `;

    container.querySelector('#an-trends-panel').innerHTML = `
      <div class="panel-header">
        <div><h2 class="panel-title">Daily Verification Activity Trend</h2><p class="panel-subtitle">Matches vs rejections across recent dates</p></div>
      </div>
      <canvas class="chart-canvas" id="an-trend-canvas" width="520" height="220"></canvas>
    `;
    chartCleanups.push(
      observeResponsiveChart(container.querySelector('#an-trend-canvas'), (cv) =>
        drawVerificationTrendChart(cv, verifications)
      )
    );

    container.querySelector('#an-modcomp-panel').innerHTML = `
      <div class="panel-header">
        <div><h2 class="panel-title">Modality Similarity vs Labeled Accuracy</h2><p class="panel-subtitle">Mean similarity compared against ground-truth accuracy per modality</p></div>
      </div>
      <canvas class="chart-canvas" id="an-modcomp-canvas" width="520" height="220"></canvas>
    `;
    chartCleanups.push(
      observeResponsiveChart(container.querySelector('#an-modcomp-canvas'), (cv) =>
        drawModalityComparisonChart(cv, report.perModality)
      )
    );

    const rocPanel = container.querySelector('#an-roc-panel');
    const currentThr = Number(s.faceThreshold ?? 0.72);
    if (c.roc.length === 0) {
      rocPanel.innerHTML = `
        <div class="panel-header">
          <div><h2 class="panel-title">ROC &amp; FAR / FRR Operating Curves</h2><p class="panel-subtitle">Computed exclusively from ground-truth labeled genuine and impostor trials</p></div>
        </div>
        <div class="empty-state">
          <div class="empty-title">Need both Genuine and Impostor labeled trials for ROC &amp; EER curves</div>
          <div class="empty-desc">Run Genuine-labeled and Impostor-labeled evaluation trials to plot true FAR, FRR, EER, and AUC curves.</div>
        </div>
      `;
    } else {
      rocPanel.innerHTML = `
        <div class="panel-header">
          <div>
            <h2 class="panel-title">ROC &amp; FAR / FRR Operating Curves</h2>
            <p class="panel-subtitle">Observed AUC ${c.auc.toFixed(3)} · EER ${fmtPct(c.eer)} @ ${c.eerThreshold.toFixed(2)} across ${c.sampleCount} labeled trial(s)</p>
          </div>
          <span class="meta-line">Current face threshold: <strong class="mono">${currentThr.toFixed(2)}</strong></span>
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
      chartCleanups.push(
        observeResponsiveChart(rocPanel.querySelector('#an-roc-canvas'), (cv) =>
          drawRocChart(cv, c.roc, currentThr, c.auc)
        ),
        observeResponsiveChart(rocPanel.querySelector('#an-far-canvas'), (cv) =>
          drawFarFrrChart(cv, c.roc, currentThr, c.eerThreshold)
        )
      );
    }

    container.querySelector('#an-modalities').innerHTML = `
      <div class="panel-header">
        <div><h2 class="panel-title">Per-Modality Breakdown</h2><p class="panel-subtitle">Observed similarity &amp; ground-truth accuracy per modality</p></div>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Modality</th><th class="num-col">Evaluations</th><th class="num-col">Mean Sim</th><th class="num-col">Labeled Acc</th><th>Data Status</th></tr></thead>
          <tbody>
            ${['face', 'voice', 'fingerprint', 'multimodal']
              .map((m) => {
                const pm = report.perModality[m];
                const accTxt = pm.metrics ? fmtPct(pm.metrics.accuracy) : '—';
                const statusTxt = !pm.metrics
                  ? 'No labeled data'
                  : pm.metrics.insufficientData
                  ? `${pm.labeledCount} labeled (<3/class)`
                  : `${pm.labeledCount} labeled`;
                return `
                <tr>
                  <td style="text-transform:capitalize;"><strong>${m === 'multimodal' ? 'Overall Multimodal' : m}</strong></td>
                  <td class="num-col">${pm.totalEvaluations}</td>
                  <td class="num-col">${pm.meanSimilarity !== null ? fmtPct(pm.meanSimilarity) : '—'}</td>
                  <td class="num-col">${accTxt}</td>
                  <td class="meta-line">${escapeHtml(statusTxt)}</td>
                </tr>`;
              })
              .join('')}
          </tbody>
        </table>
      </div>
    `;

    const fsTel = getFirestoreTelemetry();
    container.querySelector('#an-latency-panel').innerHTML = `
      <div class="panel-header">
        <div><h2 class="panel-title">Performance, Latency &amp; Rejection Reasons</h2><p class="panel-subtitle">Measured server matching speed and Firestore client telemetry</p></div>
      </div>
      <div class="divider-list" style="font-size:13.5px;">
        <div class="divider-row">
          <span>Verification Server Latency (${report.latency.measuredCount} timed)</span>
          <span class="mono">${report.latency.avgMs !== null ? `avg ${report.latency.avgMs}ms · p50 ${report.latency.p50Ms}ms · p95 ${report.latency.p95Ms}ms · max ${report.latency.maxMs}ms` : 'No timed v2.0 records yet'}</span>
        </div>
        <div class="divider-row">
          <span>Firestore Client Ops (session)</span>
          <span class="mono">${fsTel.opsCount} ops (${fsTel.reads} reads, ${fsTel.writes} writes${fsTel.avgLatencyMs ? `, avg ${fsTel.avgLatencyMs}ms` : ''})</span>
        </div>
        <div class="divider-row">
          <span>Average Behavioral Risk Score</span>
          <span class="mono">${report.avgRiskScore !== null ? `${report.avgRiskScore} / 100` : '—'}</span>
        </div>
      </div>
      ${
        report.failedBreakdown.length > 0
          ? `<div class="stack-sm" style="padding-top:10px;border-top:1px solid var(--border-hairline);">
              <strong style="font-size:13px;">Non-Match / Rejection Breakdown</strong>
              ${report.failedBreakdown.slice(0, 6).map((f) => `<div class="row-between" style="font-size:12.5px;"><span class="mono">${escapeHtml(f.reasonCode)}</span><strong>${f.count}</strong></div>`).join('')}
            </div>`
          : `<div class="meta-line">No rejected or un-evaluated attempts in current filter window.</div>`
      }
    `;
  };

  renderStats();

  const customBox = container.querySelector('#an-custom-dates');
  container.querySelectorAll('#an-days .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('#an-days .segmented-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      daysFilter = btn.dataset.days;
      customBox.hidden = daysFilter !== 'custom';
      if (daysFilter !== 'custom') renderStats();
    });
  });

  container.querySelector('#an-apply-custom').addEventListener('click', () => {
    customStart = container.querySelector('#an-start').value;
    customEnd = container.querySelector('#an-end').value;
    renderStats();
  });

  container.querySelectorAll('#an-scope .segmented-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      container.querySelectorAll('#an-scope .segmented-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      scopeFilter = btn.dataset.scope;
      renderStats();
    });
  });

  container.querySelector('#an-export-csv').addEventListener('click', () => {
    const header = 'verificationId,identityRef,pipeline,modalities,outcome,finalDecision,policyDecision,reasonCode,score,confidence,identityConfidence,sampleQualityScore,livenessConfidence,confidenceBand,conflictDetected,groundTruth,isTestProbe,processingTimeMs,faceScore,voiceScore,fingerprintScore,riskScore,riskLevel,livenessStatus,livenessPassed,adaptiveApplied\n';
    const lines = getFilteredVerifications()
      .map((v) =>
        [
          v.verificationId,
          v.identityRef,
          v.pipeline,
          (v.modalities || []).join('+'),
          v.outcome,
          v.finalDecision ?? '',
          v.policyDecision,
          v.reasonCode,
          v.score,
          v.confidence ?? '',
          v.identityConfidence ?? '',
          v.sampleQualityScore ?? '',
          v.livenessConfidence ?? '',
          v.confidenceBand ?? '',
          v.conflictDetected ?? '',
          v.groundTruth ?? 'unlabeled',
          v.isTestProbe ?? false,
          v.processingTimeMs ?? '',
          v.faceScore ?? '',
          v.voiceScore ?? '',
          v.fingerprintScore ?? '',
          v.riskScore ?? '',
          v.riskLevel ?? '',
          v.livenessStatus ?? '',
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
      filters: { daysFilter, scopeFilter, customStart, customEnd },
      analyticsReport: latestReport,
      verifications: getFilteredVerifications(),
      securityAlerts: appState.alerts,
      approvals: appState.approvals,
    };
    downloadFile('bioguardx_security_report.json', JSON.stringify(report, null, 2), 'application/json');
    showToast('Exported Security Report JSON.', 'success');
  });

  return () => clearCharts();
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
        <h1 class="page-title">Threat Monitoring</h1>
        <p class="page-subtitle">Investigate spoofing detections, high-risk attempts, security alerts, and recommended actions.</p>
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
        <input type="search" class="input responsive-search" id="ti-search" placeholder="Search alert category or description..." />
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
                      .map((v) => {
                        const lStat = v.livenessStatus || (v.livenessPassed === true ? 'LIVENESS PASSED' : v.livenessPassed === false ? 'LIVENESS FAILED' : 'INCONCLUSIVE');
                        const lCls = lStat === 'LIVENESS PASSED' ? 'state-success' : lStat === 'LIVENESS FAILED' ? 'state-danger' : 'state-warning';
                        const dec = v.finalDecision || (v.outcome === 'match' ? 'VERIFIED' : v.outcome === 'no_match' ? 'REJECTED' : 'INCONCLUSIVE');
                        const decCls = dec === 'VERIFIED' ? 'state-success' : dec === 'REJECTED' ? 'state-danger' : 'state-warning';
                        return `
                      <tr>
                        <td class="mono"><strong>${escapeHtml(v.identityRef)}</strong></td>
                        <td class="mono">${escapeHtml(v.pipeline)}</td>
                        <td><span class="state-text ${decCls}">${escapeHtml(dec)}</span></td>
                        <td><span class="state-text ${lCls}">${escapeHtml(lStat)}</span></td>
                        <td class="mono">${v.riskScore ?? '—'} (${escapeHtml(v.riskLevel || 'low')})</td>
                        <td class="mono" style="font-size:12px;">${escapeHtml(v.reasonCode)}</td>
                        <td><button type="button" class="btn btn-ghost btn-sm" data-ai-ver="${escapeHtml(v.verificationId)}">Explain in AI</button></td>
                      </tr>`;
                      })
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

  let tiTimer = null;
  container.querySelector('#ti-search').addEventListener('input', (e) => {
    clearTimeout(tiTimer);
    tiTimer = setTimeout(() => {
      searchQ = e.target.value;
      drawAlerts();
    }, 180);
  });
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
        <h1 class="page-title">Approval Requests</h1>
        <p class="page-subtitle">Controlled authorization queue for biometric deletion and policy review requests.</p>
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
              <option value="identity_status_change">identity_status_change</option>
              <option value="policy_review">policy_review</option>
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
  if (!canManage) {
    container.innerHTML = `<div class="notice-strip danger"><div><strong>Permission Denied</strong><div>Your role (${escapeHtml(appState.profile?.role || 'viewer')}) does not have permission to manage automation workflows.</div></div></div>`;
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
    btn.addEventListener('click', () => {
      const id = btn.dataset.toggleWf;
      const enabled = btn.dataset.nextEn === 'true';
      openModal({
        title: `${enabled ? 'Enable' : 'Disable'} Workflow?`,
        bodyHtml: `<p style="font-size:13.5px;color:var(--text-secondary);">Confirm changing workflow <strong class="mono">${escapeHtml(id)}</strong> state to <strong>${enabled ? 'Enabled' : 'Disabled'}</strong>.</p>`,
        footerButtons: [
          { label: 'Cancel', variant: 'btn-secondary' },
          {
            label: enabled ? 'Enable Workflow' : 'Disable Workflow',
            variant: enabled ? 'btn-primary' : 'btn-danger',
            onClick: async ({ close }) => {
              try {
                await updateWorkflowDoc(id, { enabled });
                await appendAuditLog({ action: 'workflow_toggled', resourceType: 'workflow', resourceId: id, result: `enabled=${enabled}` });
                close();
                showToast(`Workflow ${enabled ? 'enabled' : 'disabled'}.`, 'success');
              } catch (err) {
                showToast(err.message, 'danger');
              }
            },
          },
        ],
      });
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
        <input type="search" class="input responsive-search" id="at-search" placeholder="Filter by action, actor, resource, or request ID..." />
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
  let atTimer = null;
  container.querySelector('#at-search').addEventListener('input', (e) => {
    clearTimeout(atTimer);
    atTimer = setTimeout(() => {
      q = e.target.value;
      drawLogs();
    }, 180);
  });

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
