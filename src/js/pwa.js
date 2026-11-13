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

export function getPwaStatus() {
  return {
    standalone: isStandaloneMode(),
    canInstallPrompt: Boolean(deferredPrompt),
    ios: isIosSafari(),
    online: typeof navigator !== 'undefined' ? navigator.onLine : true,
    swRegistered,
  };
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
  if (isIosSafari()) {
    openModal({
      title: 'Install BioGuard X on iPhone / iPad',
      bodyHtml: `
        <div class="stack-md">
          <p style="font-size:14px;color:var(--text-secondary);">iOS Safari installs web apps via the browser share menu:</p>
          <ol style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:8px;font-size:13.5px;">
            <li>Tap the <strong>Share</strong> icon in Safari's toolbar.</li>
            <li>Scroll down and tap <strong>Add to Home Screen</strong>.</li>
            <li>Tap <strong>Add</strong> to launch BioGuard X in full standalone mode.</li>
          </ol>
        </div>
      `,
      footerButtons: [{ label: 'Got It', variant: 'btn-primary' }],
    });
    return;
  }
  showToast('Use your browser address bar or menu ("Install BioGuard X") to install.', 'neutral');
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
