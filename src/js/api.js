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

export function fetchApiDiagnostics() {
  return apiFetch('/api/v1/diagnostics');
}

export function rotateVaultKeys(force = false) {
  return apiFetch('/api/v1/vault/rotate', {
    method: 'POST',
    body: JSON.stringify({ force }),
  });
}

function makeIdempotencyKey() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `bgx_${Date.now()}_${Math.random().toString(36).slice(2, 12)}`;
}

export function requestLivenessChallenge(modalities) {
  const payload = Array.isArray(modalities) && modalities.length > 0 ? { modalities } : {};
  return apiFetch('/api/v1/liveness/challenge', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function enrollBiometricIdentity({ identityRef, consentRecorded, samples, quality }) {
  return apiFetch('/api/v1/identities/enroll', {
    method: 'POST',
    headers: { 'Idempotency-Key': makeIdempotencyKey() },
    body: JSON.stringify({ identityRef, consentRecorded, samples, quality }),
  });
}

export function verifyMultimodalBiometrics({
  identityRef,
  pipeline,
  fusionPolicy = 'hierarchical_adaptive',
  thresholds,
  strictLiveness,
  modalityWeights,
  challengeToken,
  samples,
  quality,
  adaptiveEnabled = true,
  groundTruth = 'unlabeled',
  isTestProbe = false,
  benchmarkMeta,
}) {
  return apiFetch('/api/v1/verification/multimodal', {
    method: 'POST',
    headers: { 'Idempotency-Key': makeIdempotencyKey() },
    body: JSON.stringify({
      identityRef,
      pipeline,
      fusionPolicy,
      thresholds,
      strictLiveness,
      modalityWeights,
      challengeToken,
      samples,
      quality,
      adaptiveEnabled,
      groundTruth,
      isTestProbe,
      ...(benchmarkMeta && typeof benchmarkMeta === 'object' ? { benchmarkMeta } : {}),
    }),
  });
}

export function compareIdentities({
  identityRefA,
  identityRefB,
  thresholds,
  fusionPolicy = 'hierarchical_adaptive',
  modalityWeights,
}) {
  return apiFetch('/api/v1/identities/compare', {
    method: 'POST',
    body: JSON.stringify({ identityRefA, identityRefB, thresholds, fusionPolicy, modalityWeights }),
  });
}

export function identifyBiometricProbe({
  sourceIdentityRef,
  excludeSelf = true,
  samples,
  quality,
  thresholds,
  fusionPolicy = 'hierarchical_adaptive',
  modalityWeights,
  topK = 5,
}) {
  return apiFetch('/api/v1/identities/identify', {
    method: 'POST',
    body: JSON.stringify({
      sourceIdentityRef,
      excludeSelf,
      samples,
      quality,
      thresholds,
      fusionPolicy,
      modalityWeights,
      topK,
    }),
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
