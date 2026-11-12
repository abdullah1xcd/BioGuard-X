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
};

export const THRESHOLD_PRESETS = [
  {
    id: 'balanced',
    label: 'Balanced (Default)',
    summary: 'Recommended general-purpose thresholds',
    faceThreshold: 0.72,
    voiceThreshold: 0.70,
    fingerprintThreshold: 0.72,
    threeModalThreshold: 0.74,
  },
  {
    id: 'strict',
    label: 'High Security',
    summary: 'Stricter matching for sensitive workflows',
    faceThreshold: 0.80,
    voiceThreshold: 0.78,
    fingerprintThreshold: 0.80,
    threeModalThreshold: 0.82,
  },
  {
    id: 'convenience',
    label: 'Low Friction',
    summary: 'Relaxed thresholds for rapid verification',
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
    optional: ['voice'],
    description: 'Fast face screening with automatic voice fusion escalation on uncertain scores.',
  },
  {
    key: 'three_modal',
    label: 'Face + Voice + FP',
    requires: ['face', 'voice', 'fingerprint'],
    optional: [],
    description: 'Weighted three-modality score fusion across all biometric factors.',
  },
  {
    key: 'face_voice',
    label: 'Face + Voice',
    requires: ['face', 'voice'],
    optional: [],
    description: 'Early feature fusion combining facial geometry and acoustic vectors.',
  },
  {
    key: 'face_fingerprint',
    label: 'Face + FP',
    requires: ['face', 'fingerprint'],
    optional: [],
    description: 'Combined facial and fingerprint ridge score verification.',
  },
  {
    key: 'voice_fingerprint',
    label: 'Voice + FP',
    requires: ['voice', 'fingerprint'],
    optional: [],
    description: 'Combined voice acoustic and fingerprint ridge verification.',
  },
  {
    key: 'face_only',
    label: 'Face Only',
    requires: ['face'],
    optional: [],
    description: 'Single-modality facial HOG + LBP descriptor match.',
  },
  {
    key: 'voice_only',
    label: 'Voice Only',
    requires: ['voice'],
    optional: [],
    description: 'Single-modality MFCC, ZCR, and RMS acoustic match.',
  },
  {
    key: 'fingerprint_only',
    label: 'Fingerprint Only',
    requires: ['fingerprint'],
    optional: [],
    description: 'Single-modality Gabor ridge orientation match.',
  },
];

export const PERMISSION_MATRIX = [
  { key: 'view_identities', label: 'View Identities', roles: ['super_admin', 'administrator', 'security_analyst', 'operator', 'viewer'] },
  { key: 'create_identity', label: 'Create / Enroll Identities', roles: ['super_admin', 'administrator', 'operator'] },
  { key: 'edit_identity', label: 'Edit / Deactivate Identities', roles: ['super_admin', 'administrator', 'operator'] },
  { key: 'delete_identity', label: 'Delete Identities (Audited)', roles: ['super_admin', 'administrator'] },
  { key: 'perform_verification', label: 'Perform Biometric Verification', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'view_analytics', label: 'View Security Analytics', roles: ['super_admin', 'administrator', 'security_analyst', 'operator', 'viewer'] },
  { key: 'view_audit_logs', label: 'View Full Audit Trail', roles: ['super_admin', 'administrator', 'security_analyst'] },
  { key: 'manage_alerts', label: 'Manage Risk & Threat Alerts', roles: ['super_admin', 'administrator', 'security_analyst'] },
  { key: 'use_ai_analyst', label: 'Use AI Security Analyst', roles: ['super_admin', 'administrator', 'security_analyst', 'operator'] },
  { key: 'manage_approvals', label: 'Approve Sensitive Biometric Actions', roles: ['super_admin', 'administrator'] },
  { key: 'manage_workflows', label: 'Manage Automation Workflows', roles: ['super_admin', 'administrator'] },
  { key: 'manage_roles', label: 'Manage Users & Roles', roles: ['super_admin', 'administrator'] },
  { key: 'change_settings', label: 'Change System Settings', roles: ['super_admin', 'administrator'] },
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
