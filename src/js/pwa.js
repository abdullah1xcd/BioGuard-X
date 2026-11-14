import { registerSW } from 'virtual:pwa-register';
import { openModal, showToast } from './ui.js';

let deferredPrompt = null;
let swRegistered = false;

export function isStandaloneMode() {
  return (
    window.matchMedia?.('(display-mode: standalone)')?.matches === true ||
    window.navigator?.standalone === true
  );
}

export function isIosSafari() {
  const ua = window.navigator?.userAgent || '';
  return /iphone|ipad|ipod/i.test(ua) && !/crios|fxios/i.test(ua);
}

export function getInstallEnvironment() {
  const ua = window.navigator?.userAgent || '';
  const isAndroid = /android/i.test(ua);
  const isIos = /iphone|ipad|ipod/i.test(ua);
  const isMacDesktop = /macintosh/i.test(ua) && !isIos;
  const isMobile = isIos || isAndroid || /mobile/i.test(ua);
  const standalone = isStandaloneMode();
  return {
    standalone,
    iosSafari: isIosSafari(),
    isIos,
    isAndroid,
    isMacDesktop,
    isMobile,
    platformLabel: isIos ? 'iPhone / iPad' : isAndroid ? 'Android Mobile' : isMacDesktop ? 'Mac Laptop' : 'Windows / Linux Laptop',
    canInstallPrompt: Boolean(deferredPrompt),
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,
    swRegistered,
  };
}

export function getPwaStatus() {
  return getInstallEnvironment();
}

export async function shareOrCopyPortableLink() {
  const shareUrl = window.location.origin;
  if (typeof navigator.share === 'function') {
    try {
      await navigator.share({
        title: 'BioGuard X — Multimodal Biometric Security',
        text: 'Open BioGuard X on this device or install it to your home screen / desktop.',
        url: shareUrl,
      });
      return;
    } catch (err) {
      if (err?.name === 'AbortError') return;
    }
  }
  try {
    await navigator.clipboard.writeText(shareUrl);
    showToast(`Copied portable app URL: ${shareUrl}`, 'success');
  } catch {
    showToast(`App URL: ${shareUrl}`, 'neutral');
  }
}

export async function triggerPwaInstall() {
  if (isStandaloneMode()) {
    showToast('BioGuard X is already running in installed standalone mode.', 'neutral');
    return;
  }
  if (deferredPrompt) {
    deferredPrompt.prompt();
    const choice = await deferredPrompt.userChoice.catch(() => ({ outcome: 'dismissed' }));
    deferredPrompt = null;
    syncInstallUi();
    if (choice.outcome === 'accepted') {
      showToast('BioGuard X installed to your device.', 'success');
    }
    return;
  }

  const env = getInstallEnvironment();
  let stepsHtml;
  let heading;

  if (env.iosSafari) {
    heading = 'Install BioGuard X on iPhone / iPad';
    stepsHtml = `
      <ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:8px;font-size:13.5px;">
        <li>Tap the <strong>Share</strong> icon in Safari's toolbar.</li>
        <li>Scroll down and tap <strong>Add to Home Screen</strong>.</li>
        <li>Tap <strong>Add</strong> to launch BioGuard X in full-screen standalone mode.</li>
      </ol>`;
  } else if (env.isAndroid) {
    heading = 'Install BioGuard X on Android';
    stepsHtml = `
      <ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:8px;font-size:13.5px;">
        <li>Open the browser menu (<strong>⋮</strong>) in Chrome or Edge.</li>
        <li>Tap <strong>Install app</strong> or <strong>Add to Home screen</strong>.</li>
        <li>Confirm <strong>Install</strong> to run BioGuard X as a portable mobile app.</li>
      </ol>`;
  } else if (env.isMacDesktop) {
    heading = 'Install BioGuard X on Laptop / Mac';
    stepsHtml = `
      <ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:8px;font-size:13.5px;">
        <li><strong>Chrome / Edge / Arc:</strong> Click the <strong>Install</strong> icon inside the right side of the address bar, or open menu → <strong>Install BioGuard X</strong>.</li>
        <li><strong>Safari (macOS):</strong> Choose <strong>File → Add to Dock…</strong> to launch it as a standalone desktop app.</li>
      </ol>`;
  } else {
    heading = 'Install BioGuard X on Laptop / Desktop';
    stepsHtml = `
      <ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:8px;font-size:13.5px;">
        <li>Open the address bar <strong>Install App</strong> icon (or browser menu <strong>⋮ → Cast, save, and share → Install BioGuard X</strong>) in Chrome or Microsoft Edge.</li>
        <li>On mobile devices, open this link in Safari (iOS) or Chrome (Android) and select <strong>Add to Home Screen / Install app</strong>.</li>
      </ol>`;
  }

  openModal({
    title: heading,
    bodyHtml: `
      <div class="stack-md">
        <p style="font-size:13.5px;color:var(--text-secondary);">Detected environment: <strong class="mono">${env.platformLabel}</strong>. BioGuard X runs natively as an installable app on laptops, tablets, and mobile phones.</p>
        ${stepsHtml}
      </div>
    `,
    footerButtons: [
      {
        label: 'Share / Copy Link',
        variant: 'btn-secondary',
        onClick: async () => {
          await shareOrCopyPortableLink();
        },
      },
      { label: 'Done', variant: 'btn-primary' },
    ],
  });
}

function syncInstallUi() {
  const slot = document.getElementById('pwa-install-slot');
  if (!slot) return;
  const show = !isStandaloneMode() && (Boolean(deferredPrompt) || isIosSafari());
  slot.hidden = !show;
}

function syncOfflineBanner() {
  const banner = document.getElementById('offline-banner');
  if (!banner) return;
  banner.hidden = navigator.onLine !== false;
}

export function initPwaUI() {
  if ('serviceWorker' in navigator) {
    try {
      registerSW({
        immediate: true,
        onRegisteredSW() {
          swRegistered = true;
        },
        onNeedRefresh() {
          showToast('A newer BioGuard X build is ready; reload to apply the update.', 'neutral');
        },
      });
    } catch {
      // Ignore SW registration failures on restricted contexts
    }
  }

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    syncInstallUi();
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    syncInstallUi();
    showToast('BioGuard X installed.', 'success');
  });

  window.addEventListener('online', () => {
    syncOfflineBanner();
    showToast('Network connection restored.', 'success');
  });
  window.addEventListener('offline', () => {
    syncOfflineBanner();
    showToast('You are offline. Verification API and Firestore writes require connectivity.', 'warning');
  });

  document.getElementById('pwa-install-btn')?.addEventListener('click', triggerPwaInstall);

  syncInstallUi();
  syncOfflineBanner();
}
