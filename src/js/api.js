import { getFreshIdToken } from './firebase.js';

async function apiFetch(url, options = {}) {
  const token = await getFreshIdToken();
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || `API request failed (${res.status})`);
    err.code = data.error || 'api_error';
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

export async function fetchApiHealth() {
  const res = await fetch('/api/v1/health');
  if (!res.ok) throw new Error(`Health endpoint returned ${res.status}`);
  return res.json();
}

export function fetchServerSession() {
  return apiFetch('/api/v1/auth/me');
}

export function enrollBiometricIdentity({ identityRef, consentRecorded, samples, quality }) {
  return apiFetch('/api/v1/identities/enroll', {
    method: 'POST',
    body: JSON.stringify({ identityRef, consentRecorded, samples, quality }),
  });
}

export function verifyMultimodalBiometrics({
  identityRef,
  pipeline,
  thresholds,
  samples,
  quality,
  adaptiveEnabled = true,
}) {
  return apiFetch('/api/v1/verification/multimodal', {
    method: 'POST',
    body: JSON.stringify({ identityRef, pipeline, thresholds, samples, quality, adaptiveEnabled }),
  });
}

export function deleteIdentityFromVault(identityRef) {
  return apiFetch(`/api/v1/identities/${encodeURIComponent(identityRef)}`, {
    method: 'DELETE',
  });
}

export function updateUserRoleOrStatus(uid, { role, status }) {
  return apiFetch(`/api/v1/admin/users/${encodeURIComponent(uid)}/role`, {
    method: 'POST',
    body: JSON.stringify({ role, status }),
  });
}

export function queryAiSecurityAnalyst({ mode = 'chat', message, history = [], context = {} }) {
  return apiFetch('/api/v1/ai/analyst', {
    method: 'POST',
    body: JSON.stringify({ mode, message, history, context }),
  });
}
