import '../css/styles.css';
import {
  onAuthChanged,
  signInWithGoogle,
  resolveAuthRedirect,
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
import { initPwaUI } from './pwa.js';
import { isAuthorizedDevAdmin, isDevTestingModeActive } from './config.js';

const DEV_MODE_STORAGE_KEY = 'bgx_dev_testing_mode';

const NAV_GROUPS = [
  {
    section: 'Overview',
    items: [
      { id: 'overview', label: 'Dashboard', icon: 'dashboard', render: renderOverview },
      {
        id: 'analytics',
        label: 'Analytics & Reports',
        icon: 'barChart',
        load: async () => (await import('./pages_ops.js')).renderAnalytics,
      },
    ],
  },
  {
    section: 'Biometric Operations',
    items: [
      { id: 'enrollment', label: 'Enrollment', icon: 'userPlus', render: renderEnrollment, requirePermission: 'create_identity' },
      { id: 'verification', label: 'Verification', icon: 'layers', render: renderVerification, requirePermission: 'perform_verification' },
      {
        id: 'compare',
        label: 'Identity Search',
        icon: 'compare',
        load: async () => (await import('./pages_compare.js')).renderCompareIdentities,
        requirePermission: 'perform_verification',
      },
      { id: 'identities', label: 'Identities', icon: 'users', render: renderIdentities },
    ],
  },
  {
    section: 'Security & Administration',
    items: [
      {
        id: 'threat_intel',
        label: 'Threat Monitoring',
        icon: 'radar',
        load: async () => (await import('./pages_ops.js')).renderThreatIntel,
        requirePermission: 'manage_alerts',
      },
      {
        id: 'ai_analyst',
        label: 'AI Security Analyst',
        icon: 'cpu',
        load: async () => (await import('./pages_admin.js')).renderAiAnalyst,
        requirePermission: 'use_ai_analyst',
      },
      {
        id: 'approvals',
        label: 'Approval Requests',
        icon: 'checkSquare',
        load: async () => (await import('./pages_ops.js')).renderApprovals,
      },
      {
        id: 'audit_trail',
        label: 'Audit Logs',
        icon: 'scroll',
        load: async () => (await import('./pages_ops.js')).renderAuditTrail,
      },
      {
        id: 'access_control',
        label: 'Access Control',
        icon: 'lock',
        load: async () => (await import('./pages_admin.js')).renderAccessControl,
      },
      {
        id: 'settings',
        label: 'Settings',
        icon: 'shieldCheck',
        load: async () => (await import('./pages_admin.js')).renderSettings,
      },
    ],
  },
  {
    section: 'Advanced Administration',
    items: [
      {
        id: 'automation',
        label: 'Automation Center',
        icon: 'workflow',
        load: async () => (await import('./pages_ops.js')).renderAutomationCenter,
        requirePermission: 'manage_workflows',
        showInSidebar: (state) => (state.workflows && state.workflows.length > 0) || isDevTestingModeActive(state),
      },
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
  devTestingMode: false,
};

let activeRoute = 'overview';
let activeCleanup = null;
let renderGeneration = 0;
let unsubs = [];

function resetAppStateData() {
  appState.permissions = [];
  appState.identities = [];
  appState.verifications = [];
  appState.auditLogs = [];
  appState.notifications = [];
  appState.alerts = [];
  appState.workflows = [];
  appState.approvals = [];
  appState.settings = null;
  appState.preselectedIdentityRef = '';
  appState.aiHistory = [];
  appState.analystInitialPrompt = '';
  appState.analystInitialMode = 'chat';
  appState.selectedVerificationId = '';
  appState.devTestingMode = false;
  try {
    sessionStorage.removeItem(DEV_MODE_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

function setDevTestingMode(enabled) {
  if (!isAuthorizedDevAdmin(appState)) {
    appState.devTestingMode = false;
    return false;
  }
  appState.devTestingMode = Boolean(enabled);
  try {
    if (appState.devTestingMode) {
      sessionStorage.setItem(DEV_MODE_STORAGE_KEY, '1');
    } else {
      sessionStorage.removeItem(DEV_MODE_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors
  }
  renderActiveView();
  return appState.devTestingMode;
}

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
    const visibleItems = g.items.filter(
      (it) => canAccessItem(it) && (typeof it.showInSidebar !== 'function' || it.showInSidebar(appState) || it.id === activeRoute)
    );
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
    const vaultMissing = apiOk && appState.health?.vault_ready === false;
    healthEl.innerHTML = `
      <div><strong class="${vaultMissing ? 'state-warning' : apiOk ? 'state-success' : 'state-danger'}">${vaultMissing ? 'Vault Unconfigured' : apiOk ? 'API Ready' : 'API Offline'}</strong>${isDevTestingModeActive(appState) ? ' · <span class="state-warning">Dev Mode</span>' : ''}</div>
      <div>Vault: ${appState.identities.length} · Sync: ${appState.firestoreOk ? 'Live' : 'Offline'}</div>
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

async function renderActiveView() {
  const gen = ++renderGeneration;
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

  document.querySelectorAll('#mobile-bottom-nav [data-route]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.route === activeRoute);
    const item = ROUTE_MAP.get(btn.dataset.route);
    btn.hidden = item ? !canAccessItem(item) : false;
  });

  const main = document.getElementById('main-content');
  let renderFn = route.render;
  if (!renderFn && typeof route.load === 'function') {
    main.innerHTML = `<section class="panel"><div class="meta-line">Loading ${escapeHtml(route.label)}...</div></section>`;
    try {
      renderFn = await route.load();
      route.render = renderFn;
    } catch (err) {
      if (gen !== renderGeneration) return;
      main.innerHTML = `<section class="panel"><div class="notice-strip danger"><div><strong>Failed to load view</strong><div>${escapeHtml(err?.message || 'Module load error')}</div></div></div></section>`;
      return;
    }
  }
  if (gen !== renderGeneration || typeof renderFn !== 'function') return;

  const maybeCleanup = renderFn(main, {
    appState,
    navigate,
    applyTheme,
    setDevTestingMode,
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
  resetAppStateData();
  appState.fbUser = fbUser;

  const conn = await testFirestoreConnection();
  appState.firestoreOk = conn.connected;

  const profile = await provisionUserProfile(fbUser);
  const serverMe = await fetchServerSession();
  appState.profile = { ...profile, role: serverMe.role, status: serverMe.status };
  appState.permissions = serverMe.permissions || [];
  try {
    appState.devTestingMode = isAuthorizedDevAdmin(appState) && sessionStorage.getItem(DEV_MODE_STORAGE_KEY) === '1';
  } catch {
    appState.devTestingMode = false;
  }
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
      if (['overview', 'identities', 'verification', 'compare', 'analytics'].includes(activeRoute)) renderActiveView();
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

  if (appState.permissions.includes('manage_alerts')) {
    unsubs.push(
      subscribeSecurityAlerts(uid, (list) => {
        appState.alerts = list;
        renderSidebar();
        if (['overview', 'threat_intel'].includes(activeRoute)) renderActiveView();
      })
    );
  }
  if (appState.permissions.includes('manage_workflows')) {
    unsubs.push(
      subscribeWorkflows(uid, (list) => {
        appState.workflows = list;
        renderSidebar();
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

  resolveAuthRedirect().catch((err) => {
    if (authError && err?.message) {
      authError.hidden = false;
      authError.textContent = err.message;
    }
  });

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
      resetAppStateData();
      appState.fbUser = null;
      appState.profile = null;
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

  const mbnIcons = { overview: 'dashboard', verification: 'layers', compare: 'compare', analytics: 'barChart' };
  document.querySelectorAll('#mobile-bottom-nav [data-route]').forEach((btn) => {
    const iconKey = mbnIcons[btn.dataset.route];
    if (iconKey && ICONS[iconKey] && !btn.querySelector('svg')) {
      btn.insertAdjacentHTML('afterbegin', ICONS[iconKey]);
    }
    btn.addEventListener('click', () => navigate(btn.dataset.route));
  });
  const moreBtn = document.getElementById('mbn-more-btn');
  if (moreBtn) {
    if (!moreBtn.querySelector('svg')) {
      moreBtn.insertAdjacentHTML(
        'afterbegin',
        `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/></svg>`
      );
    }
    moreBtn.addEventListener('click', openMobileDrawer);
  }

  initPwaUI();

  window.addEventListener('hashchange', () => {
    const next = window.location.hash.replace('#', '');
    if (ROUTE_MAP.has(next) && next !== activeRoute && appState.fbUser) {
      activeRoute = next;
      renderActiveView();
    }
  });
}

document.addEventListener('DOMContentLoaded', initApp);
