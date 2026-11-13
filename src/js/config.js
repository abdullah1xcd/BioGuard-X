export const APP_BRAND = {
  name: 'BioGuard X',
  mark: 'BG',
  subtitle: 'Adaptive Multimodal Biometric Security Platform',
};

export const DEFAULT_THRESHOLDS = {
  organizationName: 'BioGuard X Research',
  faceThreshold: 0.72,
  voiceThreshold: 0.70,
  fingerprintThreshold: 0.72,
  threeModalThreshold: 0.74,
  maxHoldHours: 4,
  fusionPolicy: 'hierarchical_adaptive',
  securityPreset: 'balanced',
};

export const FUSION_POLICIES = [
  {
    id: 'hierarchical_adaptive',
    label: 'Hierarchical Adaptive (Recommended)',
    summary: 'Quality-weighted fusion with conflict detection and Stage 2 escalation on borderline scores.',
  },
  {
    id: 'weighted_score',
    label: 'Quality-Weighted Score Fusion',
    summary: 'Combines calibrated scores weighted by modality signal quality; blocks strong cross-modality conflicts.',
  },
  {
    id: 'strict_and',
    label: 'Strict Conjunction (All Modalities Pass)',
    summary: 'Every evaluated modality AND the fused score must meet or exceed configured thresholds.',
  },
];

export const THRESHOLD_PRESETS = [
  {
    id: 'balanced',
    label: 'Balanced (Default)',
    summary: 'Recommended general-purpose calibrated thresholds',
    faceThreshold: 0.72,
    voiceThreshold: 0.70,
    fingerprintThreshold: 0.72,
    threeModalThreshold: 0.74,
  },
  {
    id: 'strict',
    label: 'High Security',
    summary: 'Stricter matching thresholds for sensitive access',
    faceThreshold: 0.80,
    voiceThreshold: 0.78,
    fingerprintThreshold: 0.80,
    threeModalThreshold: 0.82,
  },
  {
    id: 'convenience',
    label: 'Low Friction',
    summary: 'Relaxed thresholds for rapid verification flows',
    faceThreshold: 0.65,
    voiceThreshold: 0.63,
    fingerprintThreshold: 0.65,
    threeModalThreshold: 0.67,
  },
];

export const PIPELINE_CATALOG = [
  {
    key: 'hierarchical',
    label: 'Hierarchical',
    requires: ['face'],
    optional: ['voice', 'fingerprint'],
    description: 'Pretrained FaceRes-1024D screening with automatic Voice/Fingerprint fusion escalation on uncertain scores.',
  },
  {
    key: 'three_modal',
    label: 'Face + Voice + FP',
    requires: ['face', 'voice', 'fingerprint'],
    optional: [],
    description: 'Quality-weighted three-modality fusion across FaceRes-1024D, Voice-96D, and Minutiae RANSAC.',
  },
  {
    key: 'face_voice',
    label: 'Face + Voice',
    requires: ['face', 'voice'],
    optional: [],
    description: 'Quality-weighted FaceRes-1024D + 16kHz CMVN MFCC+F0 speaker verification.',
  },
  {
    key: 'face_fingerprint',
    label: 'Face + FP',
    requires: ['face', 'fingerprint'],
    optional: [],
    description: 'Combined FaceRes-1024D and Gabor+Minutiae fingerprint verification.',
  },
  {
    key: 'voice_fingerprint',
    label: 'Voice + FP',
    requires: ['voice', 'fingerprint'],
    optional: [],
    description: 'Combined 16kHz Voice-96D acoustic and Gabor+Minutiae fingerprint verification.',
  },
  {
    key: 'face_only',
    label: 'Face Only',
    requires: ['face'],
    optional: [],
    description: 'Pretrained BlazeFace + FaceMesh + HSE-FaceRes (1024-D) + Neural Anti-Spoof.',
  },
  {
    key: 'voice_only',
    label: 'Voice Only',
    requires: ['voice'],
    optional: [],
    description: '16kHz resampled spectral-subtracted CMVN 20-MFCC + Delta + Delta-Delta + F0 (96-D).',
  },
  {
    key: 'fingerprint_only',
    label: 'Fingerprint Only',
    requires: ['fingerprint'],
    optional: [],
    description: 'Gabor ridge enhancement, Zhang-Suen thinning, Crossing-Number minutiae & RANSAC alignment.',
  },
];

export const PERMISSION_MATRIX = [
  { key: 'view_identities', label: 'View Own Identities', roles: ['super_admin', 'administrator', 'security_analyst', 'operator', 'viewer'] },
  { key: 'create_identity', label: 'Create / Enroll Identities', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'edit_identity', label: 'Edit / Deactivate Identities', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'delete_identity', label: 'Delete Own Identities (Audited)', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'perform_verification', label: 'Perform Verification, 1:1 Compare & 1:N Search', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'view_analytics', label: 'View Own Security Analytics', roles: ['super_admin', 'administrator', 'security_analyst', 'operator', 'viewer'] },
  { key: 'view_audit_logs', label: 'View Own Audit Trail', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'manage_alerts', label: 'Manage Own Risk & Threat Alerts', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'use_ai_analyst', label: 'Use AI Security Analyst', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'manage_approvals', label: 'Approve Own Biometric Requests', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'manage_workflows', label: 'Manage Own Automation Workflows', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'manage_roles', label: 'Manage Platform Users & Roles', roles: ['super_admin', 'administrator'] },
  { key: 'change_settings', label: 'Change Own Threshold & Fusion Settings', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
];

export function slugifyIdentityRef(displayName) {
  const cleaned = String(displayName || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 48);
  return cleaned.length >= 2 ? cleaned : '';
}

export function recommendPipelineForModalities(modalities = []) {
  const set = new Set(modalities);
  if (set.has('face') && set.has('voice') && set.has('fingerprint')) return 'three_modal';
  if (set.has('face') && set.has('voice')) return 'hierarchical';
  if (set.has('face') && set.has('fingerprint')) return 'face_fingerprint';
  if (set.has('voice') && set.has('fingerprint')) return 'voice_fingerprint';
  if (set.has('face')) return 'face_only';
  if (set.has('voice')) return 'voice_only';
  if (set.has('fingerprint')) return 'fingerprint_only';
  return 'hierarchical';
}

export function isAuthorizedDevAdmin(state) {
  const role = state?.profile?.role;
  const perms = state?.permissions || [];
  return role === 'super_admin' || role === 'administrator' || perms.includes('manage_roles');
}

export function isDevTestingModeActive(state) {
  return Boolean(isAuthorizedDevAdmin(state) && state?.devTestingMode);
}

