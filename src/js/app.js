import '../css/styles.css';
import {
  onAuthChanged,
  signInWithGoogle,
  signOutUser,
  testFirestoreConnection,
  provisionUserProfile,
  subscribeIdentities,
  subscribeVerificationRecords,
  subscribeAuditLogs,
  subscribeNotifications,
  subscribeSecurityAlerts,
  subscribeWorkflows,
  subscribeApprovalRequests,
  markNotificationRead,
  loadSystemSettings,
  updateOwnPreferences,
  appendAuditLog,
} from './firebase.js';
import { fetchApiHealth, fetchServerSession } from './api.js';
import { ICONS } from './icons.js';
import { closeModal, escapeHtml, showToast } from './ui.js';
import {
  renderOverview,
  renderVerification,
  renderEnrollment,
  renderIdentities,
} from './pages_core.js';
import {
  renderAnalytics,
  renderThreatIntel,
  renderApprovals,
  renderAutomationCenter,
  renderAuditTrail,
} from './pages_ops.js';
import {
  renderAiAnalyst,
  renderAccessControl,
  renderSettings,
} from './pages_admin.js';

const NAV_GROUPS = [
  {
    section: 'Biometric Platform',
    items: [
      { id: 'overview', label: 'Main Dashboard', icon: 'dashboard', render: renderOverview },
      { id: 'enrollment', label: 'Biometric Enrollment', icon: 'userPlus', render: renderEnrollment, requirePermission: 'create_identity' },
      { id: 'verification', label: 'Verification Center', icon: 'layers', render: renderVerification, requirePermission: 'perform_verification' },
      { id: 'identities', label: 'Identities', icon: 'users', render: renderIdentities },
    ],
  },
  {
    section: 'Security Intelligence',
    items: [
      { id: 'threat_intel', label: 'Risk & Threat Analysis', icon: 'radar', render: renderThreatIntel, requirePermission: 'manage_alerts' },
      { id: 'ai_analyst', label: 'AI Security Analyst', icon: 'cpu', render: renderAiAnalyst, requirePermission: 'use_ai_analyst' },
    ],
  },
  {
    section: 'Administration',
    items: [
      { id: 'analytics', label: 'Analytics & Reports', icon: 'barChart', render: renderAnalytics },
      { id: 'approvals', label: 'Approval Workflow', icon: 'checkSquare', render: renderApprovals },
      { id: 'automation', label: 'Automation Center', icon: 'workflow', render: renderAutomationCenter, requireRoles: ['super_admin', 'administrator', 'security_analyst'] },
      { id: 'audit_trail', label: 'Audit Logs', icon: 'scroll', render: renderAuditTrail },
      { id: 'access_control', label: 'Access Control', icon: 'lock', render: renderAccessControl },
      { id: 'settings', label: 'Settings', icon: 'shieldCheck', render: renderSettings },
    ],
  },
];

const ROUTE_MAP = new Map();
for (const g of NAV_GROUPS) {
  for (const item of g.items) {
    ROUTE_MAP.set(item.id, item);
  }
}

const appState = {
  fbUser: null,
  profile: null,
  permissions: [],
  firestoreOk: false,
  health: null,
  identities: [],
  verifications: [],
  auditLogs: [],
  notifications: [],
  alerts: [],
  workflows: [],
  approvals: [],
  settings: null,
  preselectedIdentityRef: '',
  aiHistory: [],
  analystInitialPrompt: '',
  analystInitialMode: 'chat',
  selectedVerificationId: '',
};

let activeRoute = 'overview';
let activeCleanup = null;
let unsubs = [];

function clearSubscriptions() {
  for (const u of unsubs) {
    if (typeof u === 'function') u();
  }
  unsubs = [];
}

function canAccessItem(item) {
  if (item.requirePermission && !appState.permissions.includes(item.requirePermission)) {
    return false;
  }
  if (item.requireRoles && !item.requireRoles.includes(appState.profile?.role)) {
    return false;
  }
  return true;
}

function syncThemeToggleIcon() {
  const btn = document.getElementById('theme-toggle-btn');
  if (!btn) return;
  const isLight = document.documentElement.classList.contains('light');
  btn.innerHTML = isLight ? ICONS.moon : ICONS.sun;
  btn.setAttribute('aria-label', isLight ? 'Switch to dark theme' : 'Switch to light theme');
  btn.setAttribute('title', isLight ? 'Switch to dark theme' : 'Switch to light theme');
}

function applyTheme(theme) {
  document.documentElement.classList.toggle('light', theme === 'light');
  syncThemeToggleIcon();
}

function renderSidebar() {
  const nav = document.getElementById('sidebar-nav');
  if (!nav) return;

  const openAlerts = appState.alerts.filter((a) => a.status !== 'resolved').length;
  const pendingApprovals = appState.approvals.filter((r) => r.status === 'pending').length;

  nav.innerHTML = NAV_GROUPS.map((g) => {
    const visibleItems = g.items.filter(canAccessItem);
    if (!visibleItems.length) return '';
    return `
      <div>
        <div class="nav-group-label">${escapeHtml(g.section)}</div>
        <ul class="nav-list">
          ${visibleItems
            .map((it) => {
              const active = it.id === activeRoute;
              const badge =
                it.id === 'threat_intel' && openAlerts > 0
                  ? `<span class="nav-count">${openAlerts}</span>`
                  : it.id === 'approvals' && pendingApprovals > 0
                  ? `<span class="nav-count">${pendingApprovals}</span>`
                  : it.id === 'identities'
                  ? `<span class="nav-count">${appState.identities.length}</span>`
                  : '';
              return `
              <li>
                <button type="button" class="nav-item-btn ${active ? 'active' : ''}" data-route="${it.id}">
                  <span class="nav-item-left">${ICONS[it.icon] || ''}<span class="nav-item-label">${escapeHtml(it.label)}</span></span>
                  ${badge}
                </button>
              </li>`;
            })
            .join('')}
        </ul>
      </div>`;
  }).join('');

  nav.querySelectorAll('[data-route]').forEach((btn) => {
    btn.addEventListener('click', () => {
      navigate(btn.dataset.route);
      closeMobileDrawer();
    });
  });

  const healthEl = document.getElementById('health-indicator');
  if (healthEl) {
    const apiOk = appState.health?.status === 'ok';
    healthEl.innerHTML = `
      <div><strong class="${apiOk ? 'state-success' : 'state-danger'}">${apiOk ? 'API Ready' : 'API Offline'}</strong> · ${escapeHtml(appState.health?.feature_version || 'v1.1')}</div>
      <div>Firestore: ${appState.firestoreOk ? 'Connected' : 'Offline'} · Vault: ${appState.health?.encrypted_identities ?? 0}</div>
    `;
  }
}

function renderTopbarAccountAndAlerts() {
  const unread = appState.notifications.filter((n) => !n.read).length;
  const countEl = document.getElementById('notif-unread-count');
  if (countEl) countEl.textContent = String(unread);

  const notifPop = document.getElementById('notif-popover');
  if (notifPop) {
    notifPop.innerHTML = `
      <div class="row-between">
        <strong>Notifications (${unread} unread)</strong>
        <button type="button" class="btn btn-ghost btn-sm" id="notif-mark-all">Mark all read</button>
      </div>
      ${
        appState.notifications.length === 0
          ? `<div class="panel-subtitle">No notifications yet.</div>`
          : appState.notifications
              .slice(0, 10)
              .map(
                (n) => `
              <div class="divider-row" style="padding:8px 0;">
                <div class="stack-sm" style="gap:2px;">
                  <strong style="font-size:13px;color:${n.read ? 'var(--text-muted)' : 'var(--text-primary)'};">${escapeHtml(n.title)}</strong>
                  <span style="font-size:12px;color:var(--text-secondary);">${escapeHtml(n.message)}</span>
                </div>
                ${!n.read ? `<button type="button" class="btn btn-ghost btn-sm" data-read-notif="${escapeHtml(n.notificationId)}">Read</button>` : ''}
              </div>`
              )
              .join('')
      }
    `;

    notifPop.querySelector('#notif-mark-all')?.addEventListener('click', async () => {
      for (const n of appState.notifications.filter((x) => !x.read)) {
        await markNotificationRead(n.notificationId).catch(() => null);
      }
    });
    notifPop.querySelectorAll('[data-read-notif]').forEach((b) => {
      b.addEventListener('click', () => markNotificationRead(b.dataset.readNotif).catch(() => null));
    });
  }

  const p = appState.profile || {};
  const avatarImg = document.getElementById('topbar-avatar');
  const avatarFallback = document.getElementById('topbar-avatar-fallback');
  const nameEl = document.getElementById('topbar-user-name');

  if (nameEl) nameEl.textContent = p.displayName || p.email || 'Operator';
  if (p.photoURL && avatarImg) {
    avatarImg.src = p.photoURL;
    avatarImg.hidden = false;
    if (avatarFallback) avatarFallback.hidden = true;
  } else if (avatarFallback) {
    avatarFallback.textContent = (p.displayName || 'OP').slice(0, 2).toUpperCase();
    avatarFallback.hidden = false;
    if (avatarImg) avatarImg.hidden = true;
  }

  const accPop = document.getElementById('account-popover');
  if (accPop) {
    accPop.innerHTML = `
      <div class="stack-sm" style="gap:4px;">
        <strong>${escapeHtml(p.displayName || 'Operator')}</strong>
        <span class="mono" style="font-size:12px;color:var(--text-muted);">${escapeHtml(p.email || '')}</span>
        <span style="font-size:12.5px;color:var(--accent);">Role: ${escapeHtml(p.role || 'viewer')}</span>
      </div>
      <div class="row-wrap" style="padding-top:8px;border-top:1px solid var(--border-hairline);">
        <button type="button" class="btn btn-secondary btn-sm" id="acc-settings-btn">Settings</button>
        <button type="button" class="btn btn-danger btn-sm" id="acc-signout-btn">Sign Out</button>
      </div>
    `;
    accPop.querySelector('#acc-settings-btn')?.addEventListener('click', () => {
      accPop.hidden = true;
      navigate('settings');
    });
    accPop.querySelector('#acc-signout-btn')?.addEventListener('click', async () => {
      await appendAuditLog({ action: 'user_sign_out', resourceType: 'session', resourceId: appState.fbUser.uid, result: 'Signed out' }).catch(() => null);
      await signOutUser();
    });
  }
}

function renderActiveView() {
  if (typeof activeCleanup === 'function') {
    activeCleanup();
    activeCleanup = null;
  }
  let route = ROUTE_MAP.get(activeRoute) || ROUTE_MAP.get('overview');
  if (!canAccessItem(route)) {
    route = ROUTE_MAP.get('overview');
  }
  activeRoute = route.id;
  const pageEl = document.getElementById('breadcrumb-page');
  if (pageEl) pageEl.textContent = route.label;

  renderSidebar();
  renderTopbarAccountAndAlerts();

  const main = document.getElementById('main-content');
  const maybeCleanup = route.render(main, {
    appState,
    navigate,
    applyTheme,
  });
  if (typeof maybeCleanup === 'function') activeCleanup = maybeCleanup;
}

function navigate(routeId, opts = {}) {
  if (!ROUTE_MAP.has(routeId)) routeId = 'overview';
  if (opts.identityRef) {
    appState.preselectedIdentityRef = opts.identityRef;
  }
  if (opts.analystPrompt) {
    appState.analystInitialPrompt = opts.analystPrompt;
    appState.analystInitialMode = opts.analystMode || 'chat';
  }
  if (opts.verificationId) {
    appState.selectedVerificationId = opts.verificationId;
  }
  activeRoute = routeId;
  window.location.hash = routeId;
  renderActiveView();
}

function openMobileDrawer() {
  document.getElementById('sidebar')?.classList.add('open');
  const b = document.getElementById('sidebar-backdrop');
  if (b) b.hidden = false;
}

function closeMobileDrawer() {
  document.getElementById('sidebar')?.classList.remove('open');
  const b = document.getElementById('sidebar-backdrop');
  if (b) b.hidden = true;
}

async function bootstrapAuthenticatedSession(fbUser) {
  clearSubscriptions();
  appState.fbUser = fbUser;

  const conn = await testFirestoreConnection();
  appState.firestoreOk = conn.connected;

  const profile = await provisionUserProfile(fbUser);
  const serverMe = await fetchServerSession();
  appState.profile = { ...profile, role: serverMe.role, status: serverMe.status };
  appState.permissions = serverMe.permissions || [];
  applyTheme(appState.profile.theme || 'dark');

  appState.health = await fetchApiHealth().catch(() => null);
  appState.settings = await loadSystemSettings().catch(() => null);

  await appendAuditLog({
    action: 'user_sign_in',
    resourceType: 'session',
    resourceId: fbUser.uid,
    result: `Authenticated via Google (${serverMe.role})`,
  }).catch(() => null);

  const role = appState.profile.role;
  const uid = fbUser.uid;

  unsubs.push(
    subscribeIdentities(role, uid, (list) => {
      appState.identities = list;
      renderSidebar();
      if (['overview', 'identities', 'verification', 'analytics'].includes(activeRoute)) renderActiveView();
    })
  );
  unsubs.push(
    subscribeVerificationRecords(role, uid, (list) => {
      appState.verifications = list;
      if (['overview', 'analytics', 'threat_intel'].includes(activeRoute)) renderActiveView();
    })
  );
  unsubs.push(
    subscribeAuditLogs(role, uid, (list) => {
      appState.auditLogs = list;
      if (activeRoute === 'audit_trail') renderActiveView();
    })
  );
  unsubs.push(
    subscribeNotifications(uid, (list) => {
      appState.notifications = list;
      renderTopbarAccountAndAlerts();
    })
  );
  unsubs.push(
    subscribeApprovalRequests(role, uid, (list) => {
      appState.approvals = list;
      renderSidebar();
      if (activeRoute === 'approvals') renderActiveView();
    })
  );

  if (['super_admin', 'administrator', 'security_analyst'].includes(role)) {
    unsubs.push(
      subscribeSecurityAlerts((list) => {
        appState.alerts = list;
        renderSidebar();
        if (['overview', 'threat_intel'].includes(activeRoute)) renderActiveView();
      })
    );
    unsubs.push(
      subscribeWorkflows((list) => {
        appState.workflows = list;
        if (['overview', 'automation'].includes(activeRoute)) renderActiveView();
      })
    );
  }

  document.getElementById('auth-gate').hidden = true;
  document.getElementById('app-shell').hidden = false;
  renderActiveView();
}

function initApp() {
  const hash = window.location.hash.replace('#', '');
  if (ROUTE_MAP.has(hash)) activeRoute = hash;
  syncThemeToggleIcon();

  const authGate = document.getElementById('auth-gate');
  const appShell = document.getElementById('app-shell');
  const authError = document.getElementById('auth-error');
  const signInBtn = document.getElementById('google-signin-btn');

  signInBtn?.addEventListener('click', async () => {
    authError.hidden = true;
    signInBtn.disabled = true;
    try {
      await signInWithGoogle();
    } catch (err) {
      authError.hidden = false;
      authError.textContent = err.message || 'Google Sign-In failed.';
    } finally {
      signInBtn.disabled = false;
    }
  });

  onAuthChanged(async (fbUser) => {
    if (!fbUser) {
      clearSubscriptions();
      appState.fbUser = null;
      appState.profile = null;
      appState.aiHistory = [];
      appShell.hidden = true;
      authGate.hidden = false;
      return;
    }
    try {
      await bootstrapAuthenticatedSession(fbUser);
    } catch (err) {
      showToast(err.message, 'danger');
      authError.hidden = false;
      authError.textContent = err.message;
      appShell.hidden = true;
      authGate.hidden = false;
    }
  });

  document.getElementById('theme-toggle-btn')?.addEventListener('click', async () => {
    const nextTheme = document.documentElement.classList.contains('light') ? 'dark' : 'light';
    applyTheme(nextTheme);
    if (appState.profile) {
      appState.profile.theme = nextTheme;
      await updateOwnPreferences({ theme: nextTheme }).catch(() => null);
    }
    if (activeRoute === 'settings') renderActiveView();
  });

  document.getElementById('notif-toggle-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const np = document.getElementById('notif-popover');
    const ap = document.getElementById('account-popover');
    if (ap) ap.hidden = true;
    if (np) np.hidden = !np.hidden;
  });

  document.getElementById('account-menu-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const ap = document.getElementById('account-popover');
    const np = document.getElementById('notif-popover');
    if (np) np.hidden = true;
    if (ap) ap.hidden = !ap.hidden;
  });

  document.addEventListener('click', () => {
    const np = document.getElementById('notif-popover');
    const ap = document.getElementById('account-popover');
    if (np) np.hidden = true;
    if (ap) ap.hidden = true;
  });

  document.getElementById('brand-home-link')?.addEventListener('click', (e) => {
    e.preventDefault();
    navigate('overview');
  });
  document.getElementById('mobile-menu-btn')?.addEventListener('click', openMobileDrawer);
  document.getElementById('mobile-close-nav')?.addEventListener('click', closeMobileDrawer);
  document.getElementById('sidebar-backdrop')?.addEventListener('click', closeMobileDrawer);
  document.getElementById('modal-close-btn')?.addEventListener('click', closeModal);
  document.getElementById('modal-backdrop')?.addEventListener('click', closeModal);

  window.addEventListener('hashchange', () => {
    const next = window.location.hash.replace('#', '');
    if (ROUTE_MAP.has(next) && next !== activeRoute && appState.fbUser) {
      activeRoute = next;
      renderActiveView();
    }
  });
}

document.addEventListener('DOMContentLoaded', initApp);
