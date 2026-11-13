import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import { GoogleGenAI } from '@google/genai';
import firebaseConfigJson from './firebase-applet-config.json' with { type: 'json' };
import {
  fuseMultimodalScores,
  scoreVectorRefs,
  scoreFingerprintAgainstRefs,
  type FusionPolicy,
  type LivenessStatus,
  type ModalityName,
  type ThresholdConfig,
} from './src/shared/fusionEngine.ts';
import type { FingerprintQualityLabel, FingerprintTemplate } from './src/shared/fingerprintEngine.ts';

interface FirebaseConfig {
  projectId: string;
  firestoreDatabaseId: string;
  apiKey: string;
  authDomain: string;
}

const rootDir = process.cwd();
const firebaseConfig = firebaseConfigJson as FirebaseConfig;

export const FEATURE_VERSION = 'v2.0-multimodal';
const SUPPORTED_VERSIONS = new Set([FEATURE_VERSION, 'v1.1-classical-liveness', 'v1.0-classical']);
const BOOTSTRAPPED_ADMIN_EMAIL = 'abdullahmohamedharoon8@gmail.com';
const PORT = process.env.NODE_ENV === 'production' ? Number(process.env.PORT || 3000) : 3000;

type Role = 'super_admin' | 'administrator' | 'security_analyst' | 'operator' | 'viewer';

const ROLE_CAPABILITIES: Record<Role, string[]> = {
  super_admin: [
    'view_identities', 'create_identity', 'edit_identity', 'deactivate_identity', 'delete_identity',
    'perform_verification', 'view_analytics', 'view_audit_logs', 'manage_alerts',
    'manage_workflows', 'manage_approvals', 'manage_users', 'manage_roles', 'change_settings', 'use_ai_analyst',
  ],
  administrator: [
    'view_identities', 'create_identity', 'edit_identity', 'deactivate_identity', 'delete_identity',
    'perform_verification', 'view_analytics', 'view_audit_logs', 'manage_alerts',
    'manage_workflows', 'manage_approvals', 'manage_users', 'manage_roles', 'change_settings', 'use_ai_analyst',
  ],
  security_analyst: [
    'view_identities', 'create_identity', 'edit_identity', 'deactivate_identity', 'delete_identity',
    'perform_verification', 'view_analytics', 'view_audit_logs',
    'manage_alerts', 'manage_workflows', 'manage_approvals', 'change_settings', 'use_ai_analyst',
  ],
  operator: [
    'view_identities', 'create_identity', 'edit_identity', 'deactivate_identity', 'delete_identity',
    'perform_verification', 'view_analytics', 'view_audit_logs',
    'manage_alerts', 'manage_workflows', 'manage_approvals', 'change_settings', 'use_ai_analyst',
  ],
  viewer: ['view_identities', 'view_analytics'],
};

interface VaultEntry {
  identityRef: string;
  featureVersion: string;
  enrolledAt: string;
  updatedAt: string;
  modalities: {
    face?: number[][];
    voice?: number[][];
    fingerprint?: Array<FingerprintTemplate | number[]>;
  };
}

interface ModalityQualityInput {
  face?: {
    meanBrightness?: number;
    contrastStd?: number;
    sharpness?: number;
    spoofRiskFlag?: boolean;
    isLiveCapture?: boolean;
    frameMotionScore?: number;
    frameConsistencyCosine?: number;
    multiFrameVerified?: boolean;
    antispoofScore?: number | null;
    livenessNetScore?: number | null;
    detectionConfidence?: number;
    poseYawDeg?: number;
    posePitchDeg?: number;
    faceWidthPx?: number;
    faceHeightPx?: number;
    faceQualityScore?: number;
    captureSource?: string;
  };
  voice?: {
    durationSec?: number;
    activeSpeechSec?: number;
    inputSampleRate?: number;
    meanRms?: number;
    meanZcr?: number;
    speechSegments?: number;
    clippingRatio?: number;
    dynamicRangeDb?: number;
    snrEstimateDb?: number;
    voiceQualityScore?: number;
    voiceLivenessScore?: number;
    feedbackLabel?: string;
    spoofSignals?: string[];
    captureSource?: string;
  };
  fingerprint?: {
    ridgeDensity?: number;
    minutiaeHeuristicCount?: number;
    meanCoherence?: number;
    foregroundRatio?: number;
    sharpness?: number;
    meanWavelengthPx?: number;
    qualityScore?: number;
    qualityLabel?: FingerprintQualityLabel;
    templateStatus?: string;
    validPrint?: boolean;
    captureSource?: string;
  };
}

export class VaultSecretError extends Error {
  status = 503;
  code = 'vault_secret_not_configured';
  constructor(message = 'BIOGUARD_VAULT_SECRET environment variable must be set to at least 32 characters.') {
    super(message);
    this.name = 'VaultSecretError';
  }
}

export function isVaultSecretConfigured(): boolean {
  return Boolean(process.env.BIOGUARD_VAULT_SECRET && process.env.BIOGUARD_VAULT_SECRET.trim().length >= 32);
}

function getVaultSecrets(overrideSecret?: string): { primary: string; previous: string | null } {
  if (overrideSecret !== undefined) {
    const clean = overrideSecret.trim();
    if (clean.length < 32) {
      throw new VaultSecretError('Provided vault secret must be at least 32 characters.');
    }
    return { primary: clean, previous: null };
  }
  const primary = process.env.BIOGUARD_VAULT_SECRET?.trim() || '';
  if (primary.length < 32) {
    throw new VaultSecretError();
  }
  const prevRaw = process.env.BIOGUARD_VAULT_SECRET_PREVIOUS?.trim() || '';
  const previous = prevRaw.length >= 32 && prevRaw !== primary ? prevRaw : null;
  return { primary, previous };
}

// AES-256-GCM encrypted biometric templates stored durably in Firestore.
// v2 uses per-record 16-byte random salt + scryptSync and fails closed if BIOGUARD_VAULT_SECRET is unset.
export function encryptVaultMap(map: Record<string, VaultEntry>, overrideSecret?: string): string {
  const { primary } = getVaultSecrets(overrideSecret);
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(primary, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(map), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 2,
    kdf: 'scrypt',
    alg: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  });
}

export function decryptVaultMapWithMeta(
  raw: string,
  overrideSecret?: string
): { map: Record<string, VaultEntry>; version: number; rotatedFromPrevious: boolean; needsRotation: boolean } {
  const { primary, previous } = getVaultSecrets(overrideSecret);
  const parsed = JSON.parse(raw) as { v?: number; salt?: string; iv: string; tag: string; ciphertext: string };
  const isV2 = parsed.v === 2 && typeof parsed.salt === 'string' && parsed.salt.length > 0;
  const salt: Buffer | string = isV2 ? Buffer.from(parsed.salt!, 'base64') : 'bioguard-x-salt-v1';
  const candidates = previous ? [primary, previous] : [primary];

  let lastErr: unknown = null;
  for (let i = 0; i < candidates.length; i++) {
    try {
      const key = crypto.scryptSync(candidates[i], salt, 32);
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(parsed.iv, 'base64')
      );
      decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
      const dec = Buffer.concat([
        decipher.update(Buffer.from(parsed.ciphertext, 'base64')),
        decipher.final(),
      ]);
      const map = JSON.parse(dec.toString('utf8')) as Record<string, VaultEntry>;
      return {
        map,
        version: isV2 ? 2 : 1,
        rotatedFromPrevious: i > 0,
        needsRotation: !isV2 || i > 0,
      };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error('Failed to decrypt biometric vault record.');
}

export function decryptVaultMap(raw: string, overrideSecret?: string): Record<string, VaultEntry> {
  return decryptVaultMapWithMeta(raw, overrideSecret).map;
}

function firestoreDocUrl(docPath: string): string {
  const dbId = encodeURIComponent(firebaseConfig.firestoreDatabaseId);
  return `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/${dbId}/documents/${docPath}`;
}

async function loadVaultEntry(uid: string, identityRef: string, idToken: string): Promise<VaultEntry | null> {
  const url = firestoreDocUrl(`users/${encodeURIComponent(uid)}/biometric_vault/${encodeURIComponent(identityRef)}`);
  const response = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` } });
  if (response.status === 404) return null;
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Firestore vault document read failed (${response.status}): ${detail.slice(0, 300)}`);
  }
  const payload = (await response.json()) as {
    fields?: { encryptedPayload?: { stringValue?: string } };
  };
  const encryptedPayload = payload.fields?.encryptedPayload?.stringValue;
  if (!encryptedPayload) throw new Error('Firestore vault document is missing encryptedPayload.');
  const decrypted = decryptVaultMap(encryptedPayload);
  return decrypted[identityRef] || null;
}

async function listVaultEntriesWithMeta(
  uid: string,
  idToken: string,
  maxDocs = 500
): Promise<Array<{ entry: VaultEntry; needsRotation: boolean }>> {
  const results: Array<{ entry: VaultEntry; needsRotation: boolean }> = [];
  let pageToken = '';
  do {
    const qs = new URLSearchParams({ pageSize: '150' });
    if (pageToken) qs.set('pageToken', pageToken);
    const url = `${firestoreDocUrl(`users/${encodeURIComponent(uid)}/biometric_vault`)}?${qs.toString()}`;
    const response = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` }, signal: AbortSignal.timeout(8000) });
    if (response.status === 404) break;
    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new Error(`Firestore vault list failed (${response.status}): ${detail.slice(0, 300)}`);
    }
    const payload = (await response.json()) as {
      documents?: Array<{
        fields?: {
          identityRef?: { stringValue?: string };
          encryptedPayload?: { stringValue?: string };
        };
      }>;
      nextPageToken?: string;
    };
    for (const d of payload.documents || []) {
      const ref = d.fields?.identityRef?.stringValue;
      const enc = d.fields?.encryptedPayload?.stringValue;
      if (!enc) continue;
      try {
        const decMeta = decryptVaultMapWithMeta(enc);
        const entry = (ref && decMeta.map[ref]) || Object.values(decMeta.map)[0];
        if (entry) results.push({ entry, needsRotation: decMeta.needsRotation });
      } catch (err) {
        if (err instanceof VaultSecretError) throw err;
        // Skip individually corrupt ciphertext document rather than blocking 1:N search
      }
      if (results.length >= maxDocs) break;
    }
    pageToken = payload.nextPageToken || '';
  } while (pageToken && results.length < maxDocs);
  return results;
}

async function listVaultEntries(uid: string, idToken: string, maxDocs = 500): Promise<VaultEntry[]> {
  const rows = await listVaultEntriesWithMeta(uid, idToken, maxDocs);
  return rows.map((r) => r.entry);
}

async function saveVaultEntry(uid: string, entry: VaultEntry, idToken: string): Promise<void> {
  const identityRef = entry.identityRef;
  const url = firestoreDocUrl(`users/${encodeURIComponent(uid)}/biometric_vault/${encodeURIComponent(identityRef)}`);
  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${idToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      fields: {
        identityRef: { stringValue: identityRef },
        encryptedPayload: { stringValue: encryptVaultMap({ [identityRef]: entry }) },
        updatedAt: { timestampValue: new Date().toISOString() },
      },
    }),
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Firestore vault write failed (${response.status}): ${detail.slice(0, 300)}`);
  }
}

async function deleteVaultEntry(uid: string, identityRef: string, idToken: string): Promise<void> {
  const url = firestoreDocUrl(`users/${encodeURIComponent(uid)}/biometric_vault/${encodeURIComponent(identityRef)}`);
  const response = await fetch(url, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${idToken}` },
  });
  if (!response.ok && response.status !== 404) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Firestore vault delete failed (${response.status}): ${detail.slice(0, 300)}`);
  }
}

function l2Normalize(vec: number[]): number[] {
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm) || 1;
  return vec.map((v) => v / norm);
}

function vectorStd(vec: number[]): number {
  const mean = vec.reduce((a, b) => a + b, 0) / (vec.length || 1);
  const variance = vec.reduce((a, b) => a + (b - mean) ** 2, 0) / (vec.length || 1);
  return Math.sqrt(variance);
}

function validateVector(vec: unknown, allowedDims: number[]): { vector: number[]; dim: number } | null {
  if (!Array.isArray(vec) || !allowedDims.includes(vec.length)) return null;
  const clean: number[] = [];
  for (const item of vec) {
    if (typeof item !== 'number' || !Number.isFinite(item)) return null;
    clean.push(item);
  }
  const norm = Math.sqrt(clean.reduce((a, b) => a + b * b, 0));
  if (norm < 1e-6 || vectorStd(clean) < 1e-4) return null;
  return { vector: l2Normalize(clean), dim: clean.length };
}

function parseFaceSample(raw: unknown): { vector: number[]; dim: number; isLegacy: boolean } | null {
  const parsed = validateVector(raw, [1024, 208]);
  if (!parsed) return null;
  return { ...parsed, isLegacy: parsed.dim !== 1024 };
}

function parseVoiceSample(raw: unknown): { vector: number[]; dim: number; isLegacy: boolean } | null {
  const parsed = validateVector(raw, [96, 44]);
  if (!parsed) return null;
  return { ...parsed, isLegacy: parsed.dim !== 96 };
}

function parseFingerprintSample(raw: unknown): { template: FingerprintTemplate | number[]; isLegacy: boolean } | null {
  if (Array.isArray(raw)) {
    const vec = validateVector(raw, [130, 128]);
    if (!vec) return null;
    return { template: vec.vector, isLegacy: true };
  }
  if (!raw || typeof raw !== 'object') return null;
  const obj = raw as Record<string, unknown>;
  const desc = validateVector(obj.descriptor128, [128]);
  if (!desc || !Array.isArray(obj.minutiae)) return null;
  const minutiae = [];
  for (const item of obj.minutiae.slice(0, 64)) {
    if (!item || typeof item !== 'object') return null;
    const m = item as Record<string, unknown>;
    if (
      typeof m.x !== 'number' || !Number.isFinite(m.x) || m.x < 0 || m.x > 1 ||
      typeof m.y !== 'number' || !Number.isFinite(m.y) || m.y < 0 || m.y > 1 ||
      typeof m.theta !== 'number' || !Number.isFinite(m.theta) ||
      (m.type !== 'ending' && m.type !== 'bifurcation')
    ) {
      return null;
    }
    const rawNeighbors = Array.isArray(m.neighbors)
      ? m.neighbors.filter((n): n is number => typeof n === 'number' && Number.isFinite(n)).slice(0, 4)
      : undefined;
    minutiae.push({
      x: m.x,
      y: m.y,
      theta: m.theta,
      type: m.type as 'ending' | 'bifurcation',
      quality: typeof m.quality === 'number' && Number.isFinite(m.quality) ? m.quality : 0.7,
      ...(rawNeighbors && rawNeighbors.length >= 2 ? { neighbors: rawNeighbors } : {}),
    });
  }
  const qualityScore = typeof obj.qualityScore === 'number' ? obj.qualityScore : 70;
  const validPrint = typeof obj.validPrint === 'boolean' ? obj.validPrint : minutiae.length >= 4;
  return {
    isLegacy: false,
    template: {
      version: typeof obj.version === 'string' ? obj.version : FEATURE_VERSION,
      descriptor128: desc.vector,
      minutiae,
      ridgeDensity: typeof obj.ridgeDensity === 'number' ? obj.ridgeDensity : 40,
      meanCoherence: typeof obj.meanCoherence === 'number' ? obj.meanCoherence : 0.5,
      foregroundRatio: typeof obj.foregroundRatio === 'number' ? obj.foregroundRatio : 0.5,
      ...(typeof obj.sharpness === 'number' ? { sharpness: obj.sharpness } : {}),
      ...(typeof obj.meanWavelengthPx === 'number' ? { meanWavelengthPx: obj.meanWavelengthPx } : {}),
      qualityScore,
      ...(typeof obj.qualityLabel === 'string' ? { qualityLabel: obj.qualityLabel as FingerprintQualityLabel } : {}),
      ...(typeof obj.templateStatus === 'string'
        ? { templateStatus: obj.templateStatus as 'Valid Minutiae Template' | 'Insufficient Features' }
        : {}),
      validPrint,
    },
  };
}

// Quality & Anti-Spoofing Gate (Rejects blank/flat/silent/invalid uploads and scores signal quality)
function evaluateModalityQuality(
  modalities: { face: boolean; voice: boolean; fingerprint: boolean },
  quality: ModalityQualityInput | undefined
): {
  ok: boolean;
  errors: string[];
  warnings: string[];
  checks: Record<string, string>;
  qualityScores: { face: number; voice: number; fingerprint: number };
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  const checks: Record<string, string> = {};
  const qualityScores = { face: 78, voice: 78, fingerprint: 78 };

  if (modalities.face) {
    const fq = quality?.face;
    const isSynthetic = fq?.captureSource === 'test_sample' || fq?.captureSource === 'test_impostor';
    if (fq) {
      if (typeof fq.faceQualityScore === 'number') {
        qualityScores.face = Math.max(0, Math.min(100, Math.round(fq.faceQualityScore)));
      }
      if (!isSynthetic && typeof fq.contrastStd === 'number' && fq.contrastStd < 6) {
        errors.push(`Face image rejected: contrast too low (${fq.contrastStd}). Upload a clear, illuminated face image.`);
      } else if (!isSynthetic && typeof fq.sharpness === 'number' && fq.sharpness < 3) {
        errors.push(`Face image rejected: image is too blurry or uniform (sharpness=${fq.sharpness}).`);
      } else {
        checks.face = isSynthetic
          ? 'Synthetic QA test probe (non-camera)'
          : fq.isLiveCapture
          ? `Live webcam FaceRes-1024D quality passed (${qualityScores.face}/100)`
          : `Image FaceRes-1024D quality passed (${qualityScores.face}/100)`;
      }
      if (fq.spoofRiskFlag) {
        warnings.push('Face sample exhibits low anti-spoof confidence or flat texture detail.');
      }
    } else {
      checks.face = 'Face vector entropy verified';
    }
  }

  if (modalities.voice) {
    const vq = quality?.voice;
    const isSynthetic = vq?.captureSource === 'test_sample' || vq?.captureSource === 'test_impostor';
    if (vq) {
      if (typeof vq.voiceQualityScore === 'number') {
        qualityScores.voice = Math.max(0, Math.min(100, Math.round(vq.voiceQualityScore)));
      }
      if (typeof vq.durationSec === 'number' && vq.durationSec < 0.35) {
        errors.push(`Voice sample rejected: audio duration too short (${vq.durationSec}s). Record at least 0.6s.`);
      } else if (typeof vq.meanRms === 'number' && vq.meanRms < 0.004) {
        errors.push('Voice sample rejected: audio appears silent or below microphone threshold.');
      } else if (!isSynthetic && typeof vq.speechSegments === 'number' && vq.speechSegments < 1) {
        errors.push('Voice sample rejected: no active speech segments detected.');
      } else {
        checks.voice = `16kHz CMVN acoustic quality passed (${vq.speechSegments ?? 1} speech seg, ${qualityScores.voice}/100)`;
      }
      if (typeof vq.clippingRatio === 'number' && vq.clippingRatio > 0.12) {
        warnings.push('Voice sample shows heavy clipping (possible loudspeaker playback).');
      }
      if (Array.isArray(vq.spoofSignals) && vq.spoofSignals.length > 0) {
        warnings.push(...vq.spoofSignals);
      }
    } else {
      checks.voice = 'Voice vector entropy verified';
    }
  }

  if (modalities.fingerprint) {
    const fpq = quality?.fingerprint;
    const isSynthetic = fpq?.captureSource === 'test_sample' || fpq?.captureSource === 'test_impostor';
    if (fpq) {
      if (typeof fpq.qualityScore === 'number') {
        qualityScores.fingerprint = Math.max(0, Math.min(100, Math.round(fpq.qualityScore)));
      }
      if (!isSynthetic && fpq.qualityLabel === 'Image Too Blurry') {
        errors.push(`Image Too Blurry: Fingerprint sharpness (${fpq.sharpness ?? 'low'}) is insufficient for reliable ridge extraction.`);
      } else if (!isSynthetic && fpq.qualityLabel === 'Insufficient Ridge Details') {
        errors.push(`Insufficient Ridge Details: Only ${fpq.minutiaeHeuristicCount ?? 0} valid minutiae extracted.`);
      } else if (!isSynthetic && fpq.validPrint === false) {
        errors.push(
          `${fpq.qualityLabel || 'Poor Quality'}: Fingerprint failed ridge validation (coherence=${fpq.meanCoherence ?? 'low'}, density=${fpq.ridgeDensity ?? '—'}%, minutiae=${fpq.minutiaeHeuristicCount ?? 0}).`
        );
      } else if (typeof fpq.ridgeDensity === 'number' && (fpq.ridgeDensity < 6 || fpq.ridgeDensity > 94)) {
        errors.push(`Insufficient Ridge Details: abnormal ridge density (${fpq.ridgeDensity}%).`);
      } else if (typeof fpq.minutiaeHeuristicCount === 'number' && fpq.minutiaeHeuristicCount < 4) {
        errors.push('Insufficient Ridge Details: fewer than 4 reliable minutiae detected.');
      } else {
        checks.fingerprint = `Adaptive Gabor+ZhangSuen quality passed (${fpq.qualityLabel || 'Good Quality'}, ${fpq.minutiaeHeuristicCount ?? 'OK'} minutiae, ${qualityScores.fingerprint}/100)`;
      }
    } else {
      checks.fingerprint = 'Fingerprint template integrity verified';
    }
  }

  return { ok: errors.length === 0, errors, warnings, checks, qualityScores };
}

// Honest 4-state Liveness & Anti-Spoofing Evaluator
// Never falsely reports LIVENESS PASSED on static uploads or browser fingerprint images without hardware PAD sensors.
function evaluateLiveness(
  modalities: { face: boolean; voice: boolean; fingerprint: boolean },
  quality: ModalityQualityInput | undefined
): {
  passed: boolean;
  status: LivenessStatus;
  score: number;
  perModality: Record<string, LivenessStatus>;
  spoofSignals: string[];
  checks: string[];
} {
  let score = 0.78;
  const spoofSignals: string[] = [];
  const checks: string[] = [];
  const perModality: Record<string, LivenessStatus> = {};

  if (modalities.face) {
    const fq = quality?.face;
    const isSynthetic = fq?.captureSource === 'test_sample' || fq?.captureSource === 'test_impostor';
    if (!fq) {
      perModality.face = 'INCONCLUSIVE';
      checks.push('Face liveness: INCONCLUSIVE (no telemetry supplied)');
    } else if (isSynthetic) {
      perModality.face = 'NOT SUPPORTED';
      checks.push('Synthetic QA probe — physical camera liveness NOT SUPPORTED');
    } else {
      let faceFailed = false;
      if (typeof fq.antispoofScore === 'number' && fq.antispoofScore < 0.45) {
        score -= 0.40;
        faceFailed = true;
        spoofSignals.push(`Neural anti-spoof rejected frame (score=${fq.antispoofScore})`);
      }
      if (typeof fq.livenessNetScore === 'number' && fq.livenessNetScore < 0.35) {
        score -= 0.25;
        faceFailed = true;
        spoofSignals.push(`Face liveness network low confidence (${fq.livenessNetScore})`);
      }
      if (fq.spoofRiskFlag && (typeof fq.antispoofScore !== 'number' || fq.antispoofScore < 0.5)) {
        score -= 0.30;
        faceFailed = true;
        spoofSignals.push('Low facial high-frequency detail (possible printed photo or screen replay)');
      }

      if (fq.isLiveCapture) {
        const motionOk = typeof fq.frameMotionScore === 'number' && fq.frameMotionScore >= 0.005;
        if (!motionOk) {
          score -= 0.36;
          faceFailed = true;
          spoofSignals.push(`Static webcam feed detected (motion=${fq.frameMotionScore ?? 0}; possible photo/screen spoof)`);
        }
        if (faceFailed) {
          perModality.face = 'LIVENESS FAILED';
        } else {
          score = Math.min(0.98, Math.max(score, 0.86) + 0.08);
          perModality.face = 'LIVENESS PASSED';
          checks.push(`Live multi-frame motion verified (delta=${fq.frameMotionScore}${typeof fq.antispoofScore === 'number' ? `, neural=${Math.round(fq.antispoofScore * 100)}%` : ''})`);
        }
      } else {
        perModality.face = faceFailed ? 'LIVENESS FAILED' : 'INCONCLUSIVE';
        if (!faceFailed) {
          score = Math.min(score, 0.68);
          checks.push('Static image upload: active liveness challenge INCONCLUSIVE (pass-through texture screening only)');
        }
      }
    }
  }

  if (modalities.voice) {
    const vq = quality?.voice;
    const isSynthetic = vq?.captureSource === 'test_sample' || vq?.captureSource === 'test_impostor';
    if (!vq) {
      perModality.voice = 'INCONCLUSIVE';
      checks.push('Voice liveness: INCONCLUSIVE (no acoustic telemetry)');
    } else if (isSynthetic) {
      perModality.voice = 'NOT SUPPORTED';
    } else if (typeof vq.clippingRatio === 'number' && vq.clippingRatio > 0.12) {
      score -= 0.34;
      perModality.voice = 'LIVENESS FAILED';
      spoofSignals.push(`Audio clipping (${(vq.clippingRatio * 100).toFixed(1)}%) indicates possible speaker replay`);
    } else if (typeof vq.dynamicRangeDb === 'number' && vq.dynamicRangeDb < 6) {
      score -= 0.30;
      perModality.voice = 'LIVENESS FAILED';
      spoofSignals.push(`Low acoustic dynamic range (${vq.dynamicRangeDb} dB)`);
    } else if (Array.isArray(vq.spoofSignals) && vq.spoofSignals.length > 0) {
      score -= 0.28;
      perModality.voice = 'LIVENESS FAILED';
      spoofSignals.push(...vq.spoofSignals);
    } else {
      perModality.voice = 'INCONCLUSIVE';
      checks.push(`Voice spectral replay check clean (DR=${vq.dynamicRangeDb ?? '—'}dB, SNR=${vq.snrEstimateDb ?? '—'}dB); randomized passphrase challenge not enforced (INCONCLUSIVE)`);
    }
  }

  if (modalities.fingerprint) {
    const fpq = quality?.fingerprint;
    if (fpq && fpq.validPrint === false && fpq.captureSource !== 'test_sample') {
      score -= 0.38;
      perModality.fingerprint = 'LIVENESS FAILED';
      spoofSignals.push('Fingerprint ridge coherence/structure outside natural bounds');
    } else {
      perModality.fingerprint = 'NOT SUPPORTED';
      checks.push('Fingerprint hardware PAD / live sweat-pore liveness sensor NOT SUPPORTED in browser upload mode');
    }
  }

  const vals = Object.values(perModality);
  let status: LivenessStatus = 'INCONCLUSIVE';
  if (vals.includes('LIVENESS FAILED') || spoofSignals.length > 0) {
    status = 'LIVENESS FAILED';
  } else if (perModality.face === 'LIVENESS PASSED') {
    status = 'LIVENESS PASSED';
  } else if (vals.length > 0 && vals.every((v) => v === 'NOT SUPPORTED')) {
    status = 'NOT SUPPORTED';
  } else {
    status = 'INCONCLUSIVE';
  }

  const clamped = Number(Math.max(0.05, Math.min(0.99, score)).toFixed(2));
  return {
    passed: status !== 'LIVENESS FAILED' && clamped >= 0.45,
    status,
    score: clamped,
    perModality,
    spoofSignals,
    checks,
  };
}

// Behavioral & Verification Risk Engine
const verificationHistory = new Map<string, Array<{ ts: number; outcome: string; spoof: boolean }>>();

function computeRiskAssessment(params: {
  uid: string;
  identityRef: string;
  pipeline: string;
  enrolledModalitiesCount: number;
  liveness: { passed: boolean; score: number; spoofSignals: string[] };
  preliminaryScore: number;
  baseThreshold: number;
  conflictDetected: boolean;
}) {
  const now = Date.now();
  const windowMs = 15 * 60_000;
  const historyKey = `${params.uid}:${params.identityRef}`;
  const recent = (verificationHistory.get(historyKey) || []).filter((e) => now - e.ts < windowMs);
  const recentFailures = recent.filter((e) => e.outcome === 'no_match').length;
  const recentSpoofs = recent.filter((e) => e.spoof).length;

  let riskScore = 8;
  const factors: string[] = [];

  if (recentFailures > 0) {
    const add = Math.min(45, recentFailures * 16);
    riskScore += add;
    factors.push(`${recentFailures} failed verification attempt(s) in last 15 min (+${add})`);
  }
  if (recentSpoofs > 0) {
    riskScore += 20;
    factors.push('Prior spoofing/liveness alert recorded in session window (+20)');
  }
  if (!params.liveness.passed) {
    riskScore += 45;
    factors.push(`Liveness check failed: ${params.liveness.spoofSignals[0] || 'spoof signal'} (+45)`);
  }
  if (params.conflictDetected) {
    riskScore += 28;
    factors.push('Conflicting cross-modality evidence detected (+28)');
  }
  if (
    params.enrolledModalitiesCount >= 2 &&
    ['face', 'face_only', 'voice', 'voice_only', 'fingerprint', 'fingerprint_only'].includes(params.pipeline)
  ) {
    riskScore += 12;
    factors.push('Single-factor check requested on a multimodal-enrolled identity (+12)');
  }
  if (Math.abs(params.preliminaryScore - params.baseThreshold) <= 0.04) {
    riskScore += 10;
    factors.push('Similarity score falls in borderline threshold margin (+10)');
  }

  riskScore = Math.min(100, Math.max(0, riskScore));
  const riskLevel: 'low' | 'medium' | 'high' | 'critical' =
    riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';

  if (factors.length === 0) {
    factors.push('No anomalous attempt velocity, conflict, or liveness anomalies detected');
  }

  return { riskScore, riskLevel, factors, recentFailures };
}

function recordRiskEvent(uid: string, identityRef: string, outcome: string, spoof: boolean) {
  const now = Date.now();
  const historyKey = `${uid}:${identityRef}`;
  const recent = (verificationHistory.get(historyKey) || []).filter((e) => now - e.ts < 15 * 60_000);
  recent.push({ ts: now, outcome, spoof });
  verificationHistory.set(historyKey, recent);
}

async function fetchUserFirestoreRole(
  uid: string,
  email: string | undefined,
  emailVerified: boolean,
  idToken: string
): Promise<{ role: Role; status: string }> {
  if (emailVerified && email === BOOTSTRAPPED_ADMIN_EMAIL) {
    return { role: 'super_admin', status: 'active' };
  }
  try {
    const res = await fetch(firestoreDocUrl(`users/${encodeURIComponent(uid)}`), {
      headers: { Authorization: `Bearer ${idToken}` },
      signal: AbortSignal.timeout(5000),
    });
    if (res.status === 404) {
      // New or unprovisioned user defaults fail-closed to read-only viewer until profile creation
      return { role: 'viewer', status: 'active' };
    }
    if (!res.ok) {
      const err = new Error(`Authorization service returned ${res.status}.`) as Error & { status?: number; code?: string };
      err.status = 503;
      err.code = 'authorization_unavailable';
      throw err;
    }
    const docJson = (await res.json()) as {
      fields?: {
        role?: { stringValue?: string };
        status?: { stringValue?: string };
      };
    };
    const rawRole = docJson.fields?.role?.stringValue;
    const rawStatus = docJson.fields?.status?.stringValue || 'active';
    if (rawRole && !(rawRole in ROLE_CAPABILITIES)) {
      const err = new Error(`Unrecognized account role "${rawRole}".`) as Error & { status?: number; code?: string };
      err.status = 403;
      err.code = 'invalid_role_record';
      throw err;
    }
    const validRole: Role = (rawRole as Role) || 'viewer';
    return { role: validRole, status: rawStatus };
  } catch (err) {
    if (err instanceof Error && typeof (err as Error & { status?: number }).status === 'number') {
      throw err;
    }
    const unavailable = new Error('Unable to verify RBAC authorization against Firestore.') as Error & { status?: number; code?: string };
    unavailable.status = 503;
    unavailable.code = 'authorization_unavailable';
    throw unavailable;
  }
}

interface AuthedRequest extends Request {
  auth?: {
    uid: string;
    email: string;
    emailVerified: boolean;
    role: Role;
    status: string;
    idToken: string;
    decoded: { uid: string; email?: string; email_verified?: boolean };
  };
}

const rateBuckets = new Map<string, number[]>();
let activeRateLimitMode: 'upstash_redis' | 'firestore_persistent' | 'degraded_local_fallback' =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? 'upstash_redis'
    : 'firestore_persistent';

function checkLocalRateLimit(key: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now();
  const hits = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (hits.length >= maxRequests) return false;
  hits.push(now);
  rateBuckets.set(key, hits);
  return true;
}

async function consumePersistentRateLimit(
  bucketName: string,
  maxRequests: number,
  windowMs: number,
  uid: string | undefined,
  idToken: string | undefined,
  ip: string
): Promise<{ allowed: boolean; mode: typeof activeRateLimitMode }> {
  const upstashUrl = process.env.UPSTASH_REDIS_REST_URL?.trim();
  const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();

  if (upstashUrl && upstashToken) {
    try {
      const redisKey = `bgx:rl:${bucketName}:${uid || ip}`;
      const r = await fetch(`${upstashUrl.replace(/\/$/, '')}/pipeline`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${upstashToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify([
          ['INCR', redisKey],
          ['PEXPIRE', redisKey, windowMs, 'NX'],
        ]),
        signal: AbortSignal.timeout(2500),
      });
      if (r.ok) {
        const arr = (await r.json()) as Array<{ result?: number }>;
        const count = Number(arr?.[0]?.result ?? 1);
        activeRateLimitMode = 'upstash_redis';
        return { allowed: count <= maxRequests, mode: 'upstash_redis' };
      }
    } catch {
      // Fall through cleanly to Firestore or local fallback
    }
  }

  if (uid && idToken) {
    try {
      const safeBucket = bucketName.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 48);
      const docUrl = firestoreDocUrl(`users/${encodeURIComponent(uid)}/rate_limits/${encodeURIComponent(safeBucket)}`);
      const now = Date.now();
      const alignedWindowStart = Math.floor(now / windowMs) * windowMs;
      const getRes = await fetch(docUrl, {
        headers: { Authorization: `Bearer ${idToken}` },
        signal: AbortSignal.timeout(3000),
      });
      if (getRes.status === 404) {
        const createRes = await fetch(`${docUrl}?currentDocument.exists=false`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${idToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fields: {
              bucketId: { stringValue: safeBucket },
              uid: { stringValue: uid },
              windowStartMs: { integerValue: String(alignedWindowStart) },
              count: { integerValue: '1' },
              updatedAt: { timestampValue: new Date(now).toISOString() },
            },
          }),
          signal: AbortSignal.timeout(3000),
        });
        if (createRes.ok) {
          activeRateLimitMode = 'firestore_persistent';
          return { allowed: true, mode: 'firestore_persistent' };
        }
      } else if (getRes.ok) {
        const payload = (await getRes.json()) as {
          fields?: { windowStartMs?: { integerValue?: string }; count?: { integerValue?: string } };
        };
        const prevWindow = Number(payload.fields?.windowStartMs?.integerValue || 0);
        const prevCount = Number(payload.fields?.count?.integerValue || 0);
        const sameWindow = prevWindow >= alignedWindowStart && now - prevWindow < windowMs;
        if (sameWindow && prevCount >= maxRequests) {
          activeRateLimitMode = 'firestore_persistent';
          return { allowed: false, mode: 'firestore_persistent' };
        }
        const nextCount = sameWindow ? prevCount + 1 : 1;
        const nextWindow = sameWindow ? prevWindow : alignedWindowStart;
        const patchRes = await fetch(docUrl, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${idToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fields: {
              bucketId: { stringValue: safeBucket },
              uid: { stringValue: uid },
              windowStartMs: { integerValue: String(nextWindow) },
              count: { integerValue: String(nextCount) },
              updatedAt: { timestampValue: new Date(now).toISOString() },
            },
          }),
          signal: AbortSignal.timeout(3000),
        });
        if (patchRes.ok) {
          activeRateLimitMode = 'firestore_persistent';
          return { allowed: true, mode: 'firestore_persistent' };
        }
      }
    } catch {
      // Fall back safely to local rate bucket without breaking authenticated requests on transient blip
    }
  }

  activeRateLimitMode = 'degraded_local_fallback';
  const allowed = checkLocalRateLimit(`${bucketName}:${uid || ip}`, maxRequests, windowMs);
  return { allowed, mode: 'degraded_local_fallback' };
}

function rateLimit(maxRequests: number, windowMs: number, bucketName?: string) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const name = bucketName || req.path.replace(/[^a-zA-Z0-9_-]/g, '_');
    void consumePersistentRateLimit(name, maxRequests, windowMs, req.auth?.uid, req.auth?.idToken, req.ip || 'anon')
      .then((result) => {
        if (!result.allowed) {
          res.status(429).json({
            error: 'rate_limit_exceeded',
            message: 'Too many requests in the current window. Please wait briefly and retry.',
          });
          return;
        }
        next();
      })
      .catch(next);
  };
}

async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'missing_token', message: 'Authorization Bearer token is required.' });
    return;
  }
  const idToken = header.slice(7).trim();
  if (!idToken) {
    res.status(401).json({ error: 'invalid_token', message: 'Empty Bearer token.' });
    return;
  }
  try {
    const lookup = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
        signal: AbortSignal.timeout(6000),
      }
    );
    if (!lookup.ok) throw new Error('Firebase rejected the ID token.');
    const lookupPayload = (await lookup.json()) as {
      users?: Array<{ localId: string; email?: string; emailVerified?: boolean }>;
    };
    const firebaseUser = lookupPayload.users?.[0];
    if (!firebaseUser?.localId) throw new Error('Firebase user was not found for this ID token.');
    const decoded = {
      uid: firebaseUser.localId,
      email: firebaseUser.email,
      email_verified: firebaseUser.emailVerified === true,
    };
    if (!decoded.email_verified) {
      res.status(403).json({
        error: 'email_not_verified',
        message: 'A verified Google/Firebase email address is required to access BioGuard X.',
      });
      return;
    }
    const { role, status } = await fetchUserFirestoreRole(
      decoded.uid,
      decoded.email,
      Boolean(decoded.email_verified),
      idToken
    );
    if (status === 'suspended') {
      res.status(403).json({ error: 'account_suspended', message: 'Your BioGuard X operator account is suspended.' });
      return;
    }
    req.auth = {
      uid: decoded.uid,
      email: decoded.email || '',
      emailVerified: Boolean(decoded.email_verified),
      role,
      status,
      idToken,
      decoded,
    };
    next();
  } catch (err) {
    const status = typeof (err as Error & { status?: number })?.status === 'number'
      ? (err as Error & { status: number }).status
      : 401;
    const code = typeof (err as Error & { code?: string })?.code === 'string'
      ? (err as Error & { code: string }).code
      : status === 503
      ? 'authorization_unavailable'
      : 'invalid_credentials';
    const message = err instanceof Error ? err.message : 'Token verification failed.';
    res.status(status).json({ error: code, message });
  }
}

function requireCapability(capability: string) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const role = req.auth?.role || 'viewer';
    const allowed = ROLE_CAPABILITIES[role] || [];
    if (!allowed.includes(capability)) {
      res.status(403).json({
        error: 'forbidden',
        message: `Role "${role}" does not have permission "${capability}".`,
      });
      return;
    }
    next();
  };
}

function sanitizeFusionPolicy(raw: unknown): FusionPolicy {
  if (raw === 'weighted_score' || raw === 'strict_and' || raw === 'hierarchical_adaptive') {
    return raw;
  }
  return 'hierarchical_adaptive';
}

function parseThresholds(raw: Record<string, number> | undefined): ThresholdConfig {
  const clamp = (v: unknown, def: number) =>
    typeof v === 'number' && Number.isFinite(v) ? Math.min(0.98, Math.max(0.3, v)) : def;
  return {
    face: clamp(raw?.face, 0.72),
    voice: clamp(raw?.voice, 0.70),
    fingerprint: clamp(raw?.fingerprint, 0.72),
    early: clamp(raw?.early, 0.73),
    threeModal: clamp(raw?.threeModal, 0.74),
  };
}

export const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));

const asyncHandler = (
  handler: (req: AuthedRequest, res: Response) => Promise<void>
) => (req: Request, res: Response, next: NextFunction) => {
  Promise.resolve(handler(req as AuthedRequest, res)).catch(next);
};

if (process.env.VERCEL === '1') {
  app.get('/', (_req: Request, res: Response) => {
    res.redirect(302, '/index.html');
  });
}

// 1. Health Endpoint
app.get('/api/v1/health', (_req: Request, res: Response) => {
  const envVaultConfigured = isVaultSecretConfigured();
  res.status(200).json({
    status: 'ok',
    service: 'bioguard-x-api',
    feature_version: FEATURE_VERSION,
    supported_versions: [...SUPPORTED_VERSIONS],
    models: {
      face: 'BlazeFace+FaceMesh+FaceRes-1024D+AntiSpoof',
      voice: '16kHz-CMVN-MFCC20+Delta+F0-96D (Classical DSP)',
      fingerprint: 'AdaptiveGabor+ZhangSuen+2NN-RANSAC',
    },
    vault_ready: envVaultConfigured,
    vault_mode: envVaultConfigured ? 'env_secret_v2' : 'not_configured',
    rate_limit_mode: activeRateLimitMode,
    storage: 'firestore-encrypted-templates',
    firebase_project: firebaseConfig.projectId,
    firestore_database: firebaseConfig.firestoreDatabaseId,
    gemini_configured: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// 1b. Live System Health & Model Diagnostics Endpoint (Zero secrets exposed)
app.get(
  '/api/v1/diagnostics',
  requireAuth,
  rateLimit(30, 60_000, 'diagnostics'),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const t0 = performance.now();
    const envVaultConfigured = isVaultSecretConfigured();
    const geminiConfigured = Boolean(process.env.GEMINI_API_KEY);

    let firestoreStatus: 'OPERATIONAL' | 'DEGRADED' | 'OFFLINE' = 'OFFLINE';
    let firestoreLatencyMs: number | null = null;
    try {
      const f0 = performance.now();
      const fRes = await fetch(firestoreDocUrl(`users/${encodeURIComponent(req.auth!.uid)}`), {
        headers: { Authorization: `Bearer ${req.auth!.idToken}` },
        signal: AbortSignal.timeout(4000),
      });
      firestoreLatencyMs = Number((performance.now() - f0).toFixed(1));
      firestoreStatus = fRes.ok || fRes.status === 404 ? 'OPERATIONAL' : fRes.status === 403 ? 'DEGRADED' : 'OFFLINE';
    } catch {
      firestoreStatus = 'OFFLINE';
    }

    let vaultNeedsRotation = 0;
    let vaultEntriesCount = 0;
    if (envVaultConfigured && firestoreStatus === 'OPERATIONAL') {
      try {
        const metaRows = await listVaultEntriesWithMeta(req.auth!.uid, req.auth!.idToken, 100);
        vaultEntriesCount = metaRows.length;
        vaultNeedsRotation = metaRows.filter((r) => r.needsRotation).length;
      } catch {
        // Non-fatal in diagnostics
      }
    }

    res.json({
      status: 'ok',
      checkedAt: new Date().toISOString(),
      latencyMs: Number((performance.now() - t0).toFixed(1)),
      components: {
        biometricApi: { status: 'OPERATIONAL', detail: `Express API (${FEATURE_VERSION})` },
        firebaseAuth: { status: 'OPERATIONAL', detail: `Verified session (${req.auth!.role})` },
        cloudFirestore: {
          status: firestoreStatus,
          detail: firestoreLatencyMs !== null ? `Reachable (${firestoreLatencyMs} ms)` : 'Unreachable',
        },
        vaultStorage: {
          status: envVaultConfigured ? 'OPERATIONAL' : 'NOT CONFIGURED',
          detail: envVaultConfigured
            ? `AES-256-GCM v2 active (${vaultEntriesCount} record(s), ${vaultNeedsRotation} legacy/rotated)`
            : 'BIOGUARD_VAULT_SECRET (>=32 chars) not configured',
          needsRotationCount: vaultNeedsRotation,
        },
        rateLimiter: {
          status: activeRateLimitMode === 'degraded_local_fallback' ? 'DEGRADED' : 'OPERATIONAL',
          mode: activeRateLimitMode,
          detail:
            activeRateLimitMode === 'upstash_redis'
              ? 'Upstash Redis REST persistent limiter'
              : activeRateLimitMode === 'firestore_persistent'
              ? 'Firestore monotonic persistent limiter'
              : 'In-memory local fallback active',
        },
        aiAnalyst: {
          status: geminiConfigured ? 'OPERATIONAL' : 'NOT CONFIGURED',
          detail: geminiConfigured ? 'Gemini server-side endpoint ready' : 'GEMINI_API_KEY not set',
        },
        models: {
          face: { status: 'OPERATIONAL', detail: 'Client BlazeFace + FaceMesh + HSE-FaceRes 1024-D + AntiSpoof' },
          voice: { status: 'OPERATIONAL', detail: '16kHz CMVN 20-MFCC + Delta + Delta-Delta + F0 96-D' },
          fingerprint: { status: 'OPERATIONAL', detail: 'Adaptive Gabor + Zhang-Suen Thinning + 2NN-RANSAC' },
        },
      },
    });
  })
);

// 1c. Vault Key / v2 Encryption Migration Endpoint
app.post(
  '/api/v1/vault/rotate',
  requireAuth,
  requireCapability('manage_roles'),
  rateLimit(5, 60_000, 'vault_rotate'),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const force = Boolean((req.body as { force?: boolean } | undefined)?.force);
    const entries = await listVaultEntriesWithMeta(req.auth!.uid, req.auth!.idToken, 500);
    let rotatedCount = 0;
    for (const item of entries) {
      if (force || item.needsRotation) {
        await saveVaultEntry(req.auth!.uid, item.entry, req.auth!.idToken);
        rotatedCount++;
      }
    }
    res.json({
      status: 'ok',
      rotatedCount,
      totalEntries: entries.length,
      vaultVersion: 2,
    });
  })
);

// 2. Authenticated Session Introspection
app.get('/api/v1/auth/me', requireAuth, (req: AuthedRequest, res: Response) => {
  const role = req.auth!.role;
  res.json({
    uid: req.auth!.uid,
    email: req.auth!.email,
    role,
    status: req.auth!.status,
    permissions: ROLE_CAPABILITIES[role],
  });
});

// 3. Biometric Enrollment (Quality gate + AES-256-GCM encrypted server-side storage)
app.post(
  '/api/v1/identities/enroll',
  requireAuth,
  requireCapability('create_identity'),
  rateLimit(25, 60_000),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const t0 = performance.now();
    const requestId = `req_${crypto.randomUUID().slice(0, 12)}`;
    const body = req.body as {
      identityRef?: string;
      consentRecorded?: boolean;
      samples?: { face?: unknown; voice?: unknown; fingerprint?: unknown };
      quality?: ModalityQualityInput;
    };

    const identityRef = String(body.identityRef || '').trim();
    if (!/^[a-zA-Z0-9_-]{2,64}$/.test(identityRef)) {
      res.status(400).json({ error: 'invalid_identity_ref', message: 'identityRef must match ^[a-zA-Z0-9_-]{2,64}$.', requestId });
      return;
    }
    if (body.consentRecorded !== true) {
      res.status(400).json({ error: 'consent_required', message: 'Explicit biometric consent confirmation is required.', requestId });
      return;
    }

    const samples = body.samples || {};
    const faceParsed = samples.face !== undefined ? parseFaceSample(samples.face) : null;
    const voiceParsed = samples.voice !== undefined ? parseVoiceSample(samples.voice) : null;
    const fpParsed = samples.fingerprint !== undefined ? parseFingerprintSample(samples.fingerprint) : null;

    if (samples.face !== undefined && !faceParsed) {
      res.status(400).json({ error: 'invalid_face_sample', message: 'Face sample failed validation (expected 1024-D FaceRes or legacy 208-D vector).', requestId });
      return;
    }
    if (samples.voice !== undefined && !voiceParsed) {
      res.status(400).json({ error: 'invalid_voice_sample', message: 'Voice sample failed validation (expected 96-D CMVN MFCC or legacy 44-D vector).', requestId });
      return;
    }
    if (samples.fingerprint !== undefined && !fpParsed) {
      res.status(400).json({ error: 'invalid_fingerprint_sample', message: 'Fingerprint sample failed validation (expected minutiae template or legacy 130-D vector).', requestId });
      return;
    }
    if (!faceParsed && !voiceParsed && !fpParsed) {
      res.status(400).json({ error: 'no_modalities_provided', message: 'At least one valid biometric modality sample is required.', requestId });
      return;
    }

    const qualityReport = evaluateModalityQuality(
      { face: Boolean(faceParsed), voice: Boolean(voiceParsed), fingerprint: Boolean(fpParsed) },
      body.quality
    );
    if (!qualityReport.ok) {
      res.status(422).json({
        error: 'quality_check_failed',
        message: qualityReport.errors[0],
        qualityErrors: qualityReport.errors,
        requestId,
      });
      return;
    }

    const existing = await loadVaultEntry(req.auth!.uid, identityRef, req.auth!.idToken);
    const now = new Date().toISOString();
    const isAllLegacy =
      (!faceParsed || faceParsed.isLegacy) &&
      (!voiceParsed || voiceParsed.isLegacy) &&
      (!fpParsed || fpParsed.isLegacy);
    const entryVersion = isAllLegacy && existing?.featureVersion ? existing.featureVersion : FEATURE_VERSION;

    const entry: VaultEntry = existing || {
      identityRef,
      featureVersion: entryVersion,
      enrolledAt: now,
      updatedAt: now,
      modalities: {},
    };
    entry.updatedAt = now;
    entry.featureVersion = entryVersion;

    // Keep enrolled refs dimension-homogeneous per modality
    if (faceParsed) {
      const sameDim = (entry.modalities.face || []).filter((r) => r.length === faceParsed.dim);
      entry.modalities.face = [...sameDim.slice(-4), faceParsed.vector];
    }
    if (voiceParsed) {
      const sameDim = (entry.modalities.voice || []).filter((r) => r.length === voiceParsed.dim);
      entry.modalities.voice = [...sameDim.slice(-4), voiceParsed.vector];
    }
    if (fpParsed) {
      const existingFp = entry.modalities.fingerprint || [];
      const compatibleFp = Array.isArray(fpParsed.template)
        ? existingFp.filter((r) => Array.isArray(r) && r.length === (fpParsed.template as number[]).length)
        : existingFp.filter((r) => !Array.isArray(r));
      entry.modalities.fingerprint = [...compatibleFp.slice(-4), fpParsed.template];
    }

    await saveVaultEntry(req.auth!.uid, entry, req.auth!.idToken);

    const registeredModalities = Object.keys(entry.modalities).filter(
      (m) => (entry.modalities[m as keyof typeof entry.modalities]?.length || 0) > 0
    );

    const processingTimeMs = Number((performance.now() - t0).toFixed(1));
    res.status(201).json({
      status: 'enrolled',
      identityRef,
      registeredModalities,
      featureVersion: entry.featureVersion,
      qualityChecks: qualityReport.checks,
      qualityWarnings: qualityReport.warnings,
      qualityScores: qualityReport.qualityScores,
      encryptedAt: now,
      processingTimeMs,
      requestId,
    });
  })
);

// 4. Multimodal Biometric Verification (Quality + Liveness + Fusion + Conflict + Adaptive Risk)
app.post(
  '/api/v1/verification/multimodal',
  requireAuth,
  requireCapability('perform_verification'),
  rateLimit(40, 60_000),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const t0 = performance.now();
    const requestId = `ver_${crypto.randomUUID().slice(0, 12)}`;
    const body = req.body as {
      identityRef?: string;
      pipeline?: string;
      fusionPolicy?: FusionPolicy;
      adaptiveEnabled?: boolean;
      thresholds?: Record<string, number>;
      samples?: { face?: unknown; voice?: unknown; fingerprint?: unknown };
      quality?: ModalityQualityInput;
      groundTruth?: 'genuine' | 'impostor' | 'unlabeled';
      isTestProbe?: boolean;
    };

    const identityRef = String(body.identityRef || '').trim();
    const pipeline = String(body.pipeline || 'hierarchical').trim();
    const fusionPolicy = sanitizeFusionPolicy(body.fusionPolicy);
    const adaptiveEnabled = body.adaptiveEnabled !== false;

    if (!/^[a-zA-Z0-9_-]{2,64}$/.test(identityRef)) {
      res.status(400).json({ error: 'invalid_identity_ref', message: 'Valid identityRef is required.', requestId });
      return;
    }

    const entry = await loadVaultEntry(req.auth!.uid, identityRef, req.auth!.idToken);
    if (!entry) {
      res.status(404).json({
        error: 'missing_identity',
        message: `No encrypted biometric template found in vault for "${identityRef}".`,
        outcome: 'not_evaluated',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }
    if (!SUPPORTED_VERSIONS.has(entry.featureVersion)) {
      res.status(409).json({
        error: 'feature_version_mismatch',
        message: `Template version ${entry.featureVersion} is unsupported. Please re-enroll.`,
        outcome: 'not_evaluated',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }

    const samples = body.samples || {};
    const faceParsed = samples.face !== undefined ? parseFaceSample(samples.face) : null;
    const voiceParsed = samples.voice !== undefined ? parseVoiceSample(samples.voice) : null;
    const fpParsed = samples.fingerprint !== undefined ? parseFingerprintSample(samples.fingerprint) : null;

    if (
      (samples.face !== undefined && !faceParsed) ||
      (samples.voice !== undefined && !voiceParsed) ||
      (samples.fingerprint !== undefined && !fpParsed)
    ) {
      res.status(422).json({
        error: 'invalid_probe_sample',
        message: 'One or more uploaded biometric probes failed structural validation.',
        outcome: 'not_evaluated',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }

    const qualityReport = evaluateModalityQuality(
      { face: Boolean(faceParsed), voice: Boolean(voiceParsed), fingerprint: Boolean(fpParsed) },
      body.quality
    );
    if (!qualityReport.ok) {
      res.status(422).json({
        error: 'quality_check_failed',
        message: qualityReport.errors[0],
        qualityErrors: qualityReport.errors,
        outcome: 'not_evaluated',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }

    // Check version compatibility per modality
    const refsFace = entry.modalities.face || [];
    const refsVoice = entry.modalities.voice || [];
    const refsFp = entry.modalities.fingerprint || [];
    const versionMismatches: string[] = [];
    let legacyCompatibility = entry.featureVersion !== FEATURE_VERSION;

    const available: Partial<Record<ModalityName, {
      score: number;
      rawCosine?: number;
      qualityScore: number;
      details?: Record<string, unknown>;
    }>> = {};

    if (faceParsed && refsFace.length > 0) {
      const sameDimRefs = refsFace.filter((r) => r.length === faceParsed.dim);
      if (sameDimRefs.length === 0) {
        versionMismatches.push(`face (${faceParsed.dim}-D probe vs ${refsFace[0].length}-D enrolled)`);
      } else {
        const modType = faceParsed.isLegacy ? 'legacy' : 'face';
        if (faceParsed.isLegacy) legacyCompatibility = true;
        const scored = scoreVectorRefs(faceParsed.vector, sameDimRefs, modType);
        available.face = {
          score: scored.score,
          rawCosine: scored.rawCosine,
          qualityScore: qualityReport.qualityScores.face,
          details: { rawCosine: scored.rawCosine, dim: faceParsed.dim, legacy: faceParsed.isLegacy },
        };
      }
    }

    if (voiceParsed && refsVoice.length > 0) {
      const sameDimRefs = refsVoice.filter((r) => r.length === voiceParsed.dim);
      if (sameDimRefs.length === 0) {
        versionMismatches.push(`voice (${voiceParsed.dim}-D probe vs ${refsVoice[0].length}-D enrolled)`);
      } else {
        const modType = voiceParsed.isLegacy ? 'legacy' : 'voice';
        if (voiceParsed.isLegacy) legacyCompatibility = true;
        const scored = scoreVectorRefs(voiceParsed.vector, sameDimRefs, modType);
        available.voice = {
          score: scored.score,
          rawCosine: scored.rawCosine,
          qualityScore: qualityReport.qualityScores.voice,
          details: { rawCosine: scored.rawCosine, dim: voiceParsed.dim, legacy: voiceParsed.isLegacy },
        };
      }
    }

    const thr = parseThresholds(body.thresholds);

    if (fpParsed && refsFp.length > 0) {
      const scored = scoreFingerprintAgainstRefs(fpParsed.template, refsFp, thr.fingerprint);
      if (scored.details?.incompatibleTemplate) {
        versionMismatches.push('fingerprint (minutiae template vs legacy 130-D enrolled vector)');
      } else {
        if (fpParsed.isLegacy) legacyCompatibility = true;
        available.fingerprint = {
          score: scored.score,
          qualityScore: qualityReport.qualityScores.fingerprint,
          inconclusive: scored.decision === 'INCONCLUSIVE',
          decision: scored.decision,
          details: scored.details,
        };
      }
    }

    if (versionMismatches.length > 0 && Object.keys(available).length === 0) {
      res.status(409).json({
        error: 'feature_version_mismatch',
        message: `Incompatible template versions for ${versionMismatches.join(', ')}. Re-enroll this identity to upgrade it to ${FEATURE_VERSION}.`,
        outcome: 'not_evaluated',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }

    const liveness = evaluateLiveness(
      { face: Boolean(faceParsed), voice: Boolean(voiceParsed), fingerprint: Boolean(fpParsed) },
      body.quality
    );

    const fusion = fuseMultimodalScores({
      pipeline,
      fusionPolicy,
      thresholds: thr,
      available,
      livenessPassed: liveness.passed,
      livenessStatus: liveness.status,
      livenessScore: liveness.score,
    });

    if (fusion.reasonCode === 'missing_template_or_sample' || fusion.reasonCode === 'missing_face_modality') {
      res.status(422).json({
        error: fusion.reasonCode,
        message: fusion.rejectionReasons[0] || 'Required modality samples and enrolled templates are missing.',
        outcome: 'not_evaluated',
        finalDecision: 'INCONCLUSIVE',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }

    const enrolledCount = [refsFace.length > 0, refsVoice.length > 0, refsFp.length > 0].filter(Boolean).length;
    const risk = computeRiskAssessment({
      uid: req.auth!.uid,
      identityRef,
      pipeline,
      enrolledModalitiesCount: enrolledCount,
      liveness,
      preliminaryScore: fusion.finalScore,
      baseThreshold: fusion.baseThreshold,
      conflictDetected: fusion.conflictDetected,
    });

    const isSingleModality = ['face', 'face_only', 'voice', 'voice_only', 'fingerprint', 'fingerprint_only'].includes(pipeline);
    let outcome = fusion.outcome;
    let finalDecision = fusion.finalDecision;
    let reasonCode = fusion.reasonCode;
    let effectiveThreshold = fusion.baseThreshold;
    let adaptiveApplied = false;
    let adaptiveReason = '';
    const rejectionReasons = [...fusion.rejectionReasons];

    if (outcome !== 'not_evaluated' && adaptiveEnabled && risk.riskScore >= 50) {
      adaptiveApplied = true;
      if (isSingleModality && enrolledCount >= 2) {
        outcome = 'not_evaluated';
        finalDecision = 'INCONCLUSIVE';
        reasonCode = 'adaptive_mfa_escalation_required';
        adaptiveReason = `Risk score ${risk.riskScore}/100 requires multimodal verification instead of single-factor.`;
        rejectionReasons.push(adaptiveReason);
      } else {
        effectiveThreshold = Number(Math.min(0.96, fusion.baseThreshold + 0.05).toFixed(4));
        adaptiveReason = `Threshold tightened by +0.05 (from ${fusion.baseThreshold} to ${effectiveThreshold}) due to ${risk.riskLevel} risk.`;
        if (outcome === 'match' && fusion.finalScore < effectiveThreshold) {
          outcome = 'no_match';
          finalDecision = 'REJECTED';
          reasonCode = 'adaptive_threshold_not_met';
          rejectionReasons.push(adaptiveReason);
        }
      }
    }

    recordRiskEvent(req.auth!.uid, identityRef, outcome, liveness.status === 'LIVENESS FAILED');
    const processingTimeMs = Number((performance.now() - t0).toFixed(1));

    const details: Record<string, unknown> = {
      stage: fusion.stage,
      fusionExplanation: fusion.fusionExplanation,
      modalityEvaluations: fusion.modalityEvaluations,
      qualityChecks: qualityReport.checks,
      qualityWarnings: qualityReport.warnings,
      liveness,
      risk: {
        score: risk.riskScore,
        level: risk.riskLevel,
        factors: risk.factors,
      },
      conflictDetected: fusion.conflictDetected,
      conflictDetails: fusion.conflictDetails,
      rejectionReasons,
      legacyCompatibility,
      versionMismatches,
    };
    if (adaptiveApplied) {
      details.adaptive = {
        applied: true,
        baseThreshold: fusion.baseThreshold,
        effectiveThreshold,
        reason: adaptiveReason,
      };
    }

    res.json({
      status: 'ok',
      identityRef,
      pipeline,
      fusionPolicy,
      modalitiesEvaluated: fusion.modalitiesEvaluated,
      modalityEvaluations: fusion.modalityEvaluations,
      outcome,
      finalDecision,
      livenessStatus: liveness.status,
      fusionExplanation: adaptiveReason ? `${fusion.fusionExplanation} ${adaptiveReason}` : fusion.fusionExplanation,
      policy_decision: 'pending',
      reasonCode,
      score: fusion.finalScore,
      confidence: fusion.confidence,
      confidenceBand: fusion.confidenceBand,
      threshold: effectiveThreshold,
      baseThreshold: fusion.baseThreshold,
      adaptiveApplied,
      conflictDetected: fusion.conflictDetected,
      conflictDetails: fusion.conflictDetails,
      rejectionReasons,
      qualityScores: qualityReport.qualityScores,
      liveness,
      risk: {
        score: risk.riskScore,
        level: risk.riskLevel,
        factors: risk.factors,
      },
      processingTimeMs,
      legacyCompatibility,
      featureVersion: entry.featureVersion,
      details,
      requestId,
    });
  })
);

// Helper to score one VaultEntry against another VaultEntry across shared compatible modalities
function compareEntriesServer(
  entryA: VaultEntry,
  entryB: VaultEntry,
  thresholds: ThresholdConfig,
  fusionPolicy: FusionPolicy
) {
  const available: Partial<Record<ModalityName, {
    score: number;
    rawCosine?: number;
    qualityScore: number;
    details?: Record<string, unknown>;
  }>> = {};
  const incompatibleModalities: string[] = [];
  let legacyCompatibility =
    entryA.featureVersion !== FEATURE_VERSION || entryB.featureVersion !== FEATURE_VERSION;

  const faceA = entryA.modalities.face || [];
  const faceB = entryB.modalities.face || [];
  if (faceA.length > 0 && faceB.length > 0) {
    const dimA = faceA[faceA.length - 1].length;
    const sameDimB = faceB.filter((v) => v.length === dimA);
    if (sameDimB.length === 0) {
      incompatibleModalities.push(`face (${dimA}-D vs ${faceB[0].length}-D)`);
    } else {
      const modType = dimA === 1024 ? 'face' : 'legacy';
      if (dimA !== 1024) legacyCompatibility = true;
      const scored = scoreVectorRefs(faceA[faceA.length - 1], sameDimB, modType);
      available.face = {
        score: scored.score,
        rawCosine: scored.rawCosine,
        qualityScore: 85,
        details: { rawCosine: scored.rawCosine, dim: dimA },
      };
    }
  }

  const voiceA = entryA.modalities.voice || [];
  const voiceB = entryB.modalities.voice || [];
  if (voiceA.length > 0 && voiceB.length > 0) {
    const dimA = voiceA[voiceA.length - 1].length;
    const sameDimB = voiceB.filter((v) => v.length === dimA);
    if (sameDimB.length === 0) {
      incompatibleModalities.push(`voice (${dimA}-D vs ${voiceB[0].length}-D)`);
    } else {
      const modType = dimA === 96 ? 'voice' : 'legacy';
      if (dimA !== 96) legacyCompatibility = true;
      const scored = scoreVectorRefs(voiceA[voiceA.length - 1], sameDimB, modType);
      available.voice = {
        score: scored.score,
        rawCosine: scored.rawCosine,
        qualityScore: 85,
        details: { rawCosine: scored.rawCosine, dim: dimA },
      };
    }
  }

  const fpA = entryA.modalities.fingerprint || [];
  const fpB = entryB.modalities.fingerprint || [];
  if (fpA.length > 0 && fpB.length > 0) {
    const latestA = fpA[fpA.length - 1];
    const scored = scoreFingerprintAgainstRefs(latestA, fpB, thresholds.fingerprint);
    if (scored.details?.incompatibleTemplate) {
      incompatibleModalities.push('fingerprint (minutiae template vs legacy 130-D vector)');
    } else {
      if (Array.isArray(latestA)) legacyCompatibility = true;
      available.fingerprint = {
        score: scored.score,
        qualityScore: !Array.isArray(latestA) ? latestA.qualityScore : 75,
        inconclusive: scored.decision === 'INCONCLUSIVE',
        decision: scored.decision,
        details: scored.details,
      };
    }
  }

  const mods = Object.keys(available) as ModalityName[];
  let pipeline = 'three_modal';
  if (mods.length === 1) pipeline = `${mods[0]}_only`;
  else if (mods.length === 2) {
    if (mods.includes('face') && mods.includes('voice')) pipeline = 'face_voice';
    else if (mods.includes('face') && mods.includes('fingerprint')) pipeline = 'face_fingerprint';
    else pipeline = 'voice_fingerprint';
  }

  const fusion = mods.length
    ? fuseMultimodalScores({ pipeline, fusionPolicy, thresholds, available, livenessPassed: true, livenessScore: 0.9 })
    : null;

  return {
    sharedModalities: mods,
    incompatibleModalities,
    legacyCompatibility,
    fusion,
  };
}

// 5. 1:1 Identity Comparison Endpoint
app.post(
  '/api/v1/identities/compare',
  requireAuth,
  requireCapability('perform_verification'),
  rateLimit(25, 60_000),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const t0 = performance.now();
    const requestId = `cmp_${crypto.randomUUID().slice(0, 12)}`;
    const body = req.body as {
      identityRefA?: string;
      identityRefB?: string;
      fusionPolicy?: FusionPolicy;
      thresholds?: Record<string, number>;
    };

    const refA = String(body.identityRefA || '').trim();
    const refB = String(body.identityRefB || '').trim();
    if (!/^[a-zA-Z0-9_-]{2,64}$/.test(refA) || !/^[a-zA-Z0-9_-]{2,64}$/.test(refB)) {
      res.status(400).json({ error: 'invalid_identity_ref', message: 'Valid identityRefA and identityRefB are required.', requestId });
      return;
    }

    const [entryA, entryB] = await Promise.all([
      loadVaultEntry(req.auth!.uid, refA, req.auth!.idToken),
      loadVaultEntry(req.auth!.uid, refB, req.auth!.idToken),
    ]);
    if (!entryA || !entryB) {
      res.status(404).json({
        error: 'missing_identity',
        message: !entryA ? `Vault template missing for "${refA}".` : `Vault template missing for "${refB}".`,
        requestId,
      });
      return;
    }

    const thresholds = parseThresholds(body.thresholds);
    const fusionPolicy = sanitizeFusionPolicy(body.fusionPolicy);
    const cmp = compareEntriesServer(entryA, entryB, thresholds, fusionPolicy);
    const processingTimeMs = Number((performance.now() - t0).toFixed(1));

    if (!cmp.fusion) {
      res.status(422).json({
        error: 'no_compatible_modalities',
        message: cmp.incompatibleModalities.length
          ? `No compatible shared modalities (${cmp.incompatibleModalities.join(', ')}). Re-enroll both identities to ${FEATURE_VERSION}.`
          : 'Selected identities share no common enrolled biometric modalities.',
        incompatibleModalities: cmp.incompatibleModalities,
        processingTimeMs,
        requestId,
      });
      return;
    }

    res.json({
      status: 'ok',
      identityRefA: refA,
      identityRefB: refB,
      sameIdentityRef: refA === refB,
      featureVersionA: entryA.featureVersion,
      featureVersionB: entryB.featureVersion,
      legacyCompatibility: cmp.legacyCompatibility,
      incompatibleModalities: cmp.incompatibleModalities,
      sharedModalities: cmp.sharedModalities,
      fusionPolicy,
      outcome: cmp.fusion.outcome,
      fusedScore: cmp.fusion.finalScore,
      baseThreshold: cmp.fusion.baseThreshold,
      confidence: cmp.fusion.confidence,
      confidenceBand: cmp.fusion.confidenceBand,
      conflictDetected: cmp.fusion.conflictDetected,
      conflictDetails: cmp.fusion.conflictDetails,
      rejectionReasons: cmp.fusion.rejectionReasons,
      modalityEvaluations: cmp.fusion.modalityEvaluations,
      processingTimeMs,
      requestId,
    });
  })
);

// 6. 1:N Identification Search Endpoint
app.post(
  '/api/v1/identities/identify',
  requireAuth,
  requireCapability('perform_verification'),
  rateLimit(20, 60_000),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const t0 = performance.now();
    const requestId = `idn_${crypto.randomUUID().slice(0, 12)}`;
    const body = req.body as {
      sourceIdentityRef?: string;
      excludeSelf?: boolean;
      samples?: { face?: unknown; voice?: unknown; fingerprint?: unknown };
      quality?: ModalityQualityInput;
      fusionPolicy?: FusionPolicy;
      thresholds?: Record<string, number>;
      topK?: number;
    };

    const topK = Math.min(25, Math.max(1, Number(body.topK || 5)));
    const thresholds = parseThresholds(body.thresholds);
    const fusionPolicy = sanitizeFusionPolicy(body.fusionPolicy);
    const allVaultEntries = await listVaultEntries(req.auth!.uid, req.auth!.idToken, 500);

    let probeEntry: VaultEntry | null = null;
    if (body.sourceIdentityRef) {
      const ref = String(body.sourceIdentityRef).trim();
      probeEntry = allVaultEntries.find((e) => e.identityRef === ref) || null;
      if (!probeEntry) {
        res.status(404).json({ error: 'missing_identity', message: `Source identity "${ref}" not found in vault.`, requestId });
        return;
      }
    } else {
      const s = body.samples || {};
      const fp = s.face !== undefined ? parseFaceSample(s.face) : null;
      const vp = s.voice !== undefined ? parseVoiceSample(s.voice) : null;
      const fpp = s.fingerprint !== undefined ? parseFingerprintSample(s.fingerprint) : null;
      if ((s.face !== undefined && !fp) || (s.voice !== undefined && !vp) || (s.fingerprint !== undefined && !fpp)) {
        res.status(422).json({ error: 'invalid_probe_sample', message: 'One or more uploaded 1:N probe samples failed validation.', requestId });
        return;
      }
      if (!fp && !vp && !fpp) {
        res.status(400).json({ error: 'no_modalities_provided', message: 'Provide at least one biometric probe or sourceIdentityRef for 1:N search.', requestId });
        return;
      }
      const qReport = evaluateModalityQuality(
        { face: Boolean(fp), voice: Boolean(vp), fingerprint: Boolean(fpp) },
        body.quality
      );
      if (!qReport.ok) {
        res.status(422).json({ error: 'quality_check_failed', message: qReport.errors[0], qualityErrors: qReport.errors, requestId });
        return;
      }
      probeEntry = {
        identityRef: '_probe_',
        featureVersion: FEATURE_VERSION,
        enrolledAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        modalities: {
          face: fp ? [fp.vector] : undefined,
          voice: vp ? [vp.vector] : undefined,
          fingerprint: fpp ? [fpp.template] : undefined,
        },
      };
    }

    const candidates = allVaultEntries.filter((e) =>
      body.sourceIdentityRef && body.excludeSelf !== false ? e.identityRef !== body.sourceIdentityRef : true
    );

    const ranked: Array<{
      rank?: number;
      identityRef: string;
      featureVersion: string;
      sharedModalities: ModalityName[];
      fusedScore: number;
      baseThreshold: number;
      confidence: number;
      confidenceBand: string;
      outcome: string;
      conflictDetected: boolean;
      modalityScores: Record<string, number>;
      legacyCompatibility: boolean;
      incompatibleModalities: string[];
    }> = [];

    let incompatibleCandidates = 0;

    for (const candidate of candidates) {
      const cmp = compareEntriesServer(probeEntry, candidate, thresholds, fusionPolicy);
      if (!cmp.fusion) {
        if (cmp.incompatibleModalities.length > 0) incompatibleCandidates++;
        continue;
      }
      const modScores: Record<string, number> = {};
      for (const [m, ev] of Object.entries(cmp.fusion.modalityEvaluations)) {
        modScores[m] = ev.score;
      }
      ranked.push({
        identityRef: candidate.identityRef,
        featureVersion: candidate.featureVersion,
        sharedModalities: cmp.sharedModalities,
        fusedScore: cmp.fusion.finalScore,
        baseThreshold: cmp.fusion.baseThreshold,
        confidence: cmp.fusion.confidence,
        confidenceBand: cmp.fusion.confidenceBand,
        outcome: cmp.fusion.outcome,
        conflictDetected: cmp.fusion.conflictDetected,
        modalityScores: modScores,
        legacyCompatibility: cmp.legacyCompatibility,
        incompatibleModalities: cmp.incompatibleModalities,
      });
    }

    ranked.sort((a, b) => b.fusedScore - a.fusedScore);
    const topMatches = ranked.slice(0, topK).map((row, idx) => ({ ...row, rank: idx + 1 }));
    const matchesAboveThreshold = ranked.filter((r) => r.outcome === 'match').length;
    const processingTimeMs = Number((performance.now() - t0).toFixed(1));

    res.json({
      status: 'ok',
      probeSource: body.sourceIdentityRef || 'captured_probe',
      fusionPolicy,
      totalVaultIdentities: allVaultEntries.length,
      totalCandidatesEvaluated: candidates.length,
      compatibleCandidates: ranked.length,
      incompatibleCandidates,
      matchesAboveThreshold,
      rankedMatches: topMatches,
      processingTimeMs,
      requestId,
    });
  })
);

// 7. Vault Identity Status & Admin Deletion
app.get('/api/v1/identities/:identityRef/vault', requireAuth, requireCapability('view_identities'), asyncHandler(async (req: AuthedRequest, res: Response) => {
  const identityRef = String(req.params.identityRef || '');
  const entry = await loadVaultEntry(req.auth!.uid, identityRef, req.auth!.idToken);
  if (!entry) {
    res.json({ identityRef, inVault: false, modalities: [] });
    return;
  }
  const modalities = Object.keys(entry.modalities).filter(
    (m) => (entry.modalities[m as keyof typeof entry.modalities]?.length || 0) > 0
  );
  res.json({
    identityRef,
    inVault: true,
    featureVersion: entry.featureVersion,
    enrolledAt: entry.enrolledAt,
    updatedAt: entry.updatedAt,
    modalities,
  });
}));

app.delete('/api/v1/identities/:identityRef', requireAuth, requireCapability('delete_identity'), asyncHandler(async (req: AuthedRequest, res: Response) => {
  const identityRef = String(req.params.identityRef || '');
  const existing = await loadVaultEntry(req.auth!.uid, identityRef, req.auth!.idToken);
  if (!existing) {
    res.status(404).json({ error: 'not_found', message: 'Identity not present in biometric vault.' });
    return;
  }
  await deleteVaultEntry(req.auth!.uid, identityRef, req.auth!.idToken);
  res.json({ status: 'deleted_from_vault', identityRef });
}));

// 8. Server-Verified Admin Role & Status Management
app.post(
  '/api/v1/admin/users/:uid/role',
  requireAuth,
  requireCapability('manage_roles'),
  rateLimit(20, 60_000),
  async (req: AuthedRequest, res: Response) => {
    const targetUid = String(req.params.uid || '').trim();
    const body = req.body as { role?: Role; status?: 'active' | 'suspended' };
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(targetUid)) {
      res.status(400).json({ error: 'invalid_uid', message: 'Invalid target user UID.' });
      return;
    }
    if (body.role && !(body.role in ROLE_CAPABILITIES)) {
      res.status(400).json({ error: 'invalid_role', message: 'Unsupported role specified.' });
      return;
    }
    if (targetUid === req.auth!.uid && body.status === 'suspended') {
      res.status(400).json({ error: 'self_suspend_blocked', message: 'Administrators cannot suspend their own account.' });
      return;
    }

    const updateMask: string[] = [];
    const fields: Record<string, unknown> = {};
    if (body.role) {
      updateMask.push('role');
      fields.role = { stringValue: body.role };
    }
    if (body.status) {
      updateMask.push('status');
      fields.status = { stringValue: body.status };
    }
    if (!updateMask.length) {
      res.status(400).json({ error: 'empty_update', message: 'Provide role or status to update.' });
      return;
    }

    try {
      const maskQuery = updateMask.map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join('&');
      const patchRes = await fetch(`${firestoreDocUrl(`users/${encodeURIComponent(targetUid)}`)}?${maskQuery}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${req.auth!.idToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ fields }),
      });
      if (!patchRes.ok) {
        const errText = await patchRes.text();
        res.status(patchRes.status).json({ error: 'firestore_update_failed', message: errText });
        return;
      }

      if (body.role) {
        const isTargetAdmin = body.role === 'super_admin' || body.role === 'administrator';
        const adminUrl = firestoreDocUrl(`admins/${encodeURIComponent(targetUid)}`);
        if (isTargetAdmin) {
          await fetch(adminUrl, {
            method: 'PATCH',
            headers: {
              Authorization: `Bearer ${req.auth!.idToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              fields: {
                uid: { stringValue: targetUid },
                role: { stringValue: body.role },
                grantedBy: { stringValue: req.auth!.uid },
                createdAt: { timestampValue: new Date().toISOString() },
              },
            }),
          });
        } else {
          await fetch(adminUrl, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${req.auth!.idToken}` },
          });
        }
      }

      res.json({ status: 'updated', uid: targetUid, role: body.role, accountStatus: body.status });
    } catch (err) {
      res.status(500).json({ error: 'server_error', message: err instanceof Error ? err.message : 'Failed to update role.' });
    }
  }
);

// 9. AI Security Analyst (Server-Side Gemini API Only)
app.post(
  '/api/v1/ai/analyst',
  requireAuth,
  requireCapability('use_ai_analyst'),
  rateLimit(20, 60_000),
  async (req: AuthedRequest, res: Response) => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      res.status(503).json({
        error: 'gemini_not_configured',
        message: 'GEMINI_API_KEY is not configured in Settings > Secrets.',
      });
      return;
    }

    const body = req.body as {
      mode?: 'explain_verification' | 'investigate_activity' | 'summarize_incidents' | 'chat';
      message?: string;
      history?: Array<{ role: 'user' | 'model'; text: string }>;
      context?: Record<string, unknown>;
    };
    const prompt = String(body.message || '').trim();
    if (!prompt || prompt.length > 4000) {
      res.status(400).json({ error: 'invalid_prompt', message: 'Prompt must be 1 to 4000 characters.' });
      return;
    }

    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });

    const systemInstruction = [
      'You are the BioGuard X AI Security Analyst (Enterprise Multimodal Biometric Security).',
      `Current authenticated operator role: ${req.auth!.role}.`,
      `Analysis Mode: ${body.mode || 'chat'}.`,
      'Non-negotiable statistical & operational integrity rules:',
      '1. NEVER present AI-generated analysis or a single similarity score as guaranteed proof of identity.',
      '2. NEVER invent accuracy percentages, verification outcomes, EER/FAR/FRR figures, or unseen incidents.',
      '3. Distinguish strictly between: (a) Model Similarity Score, (b) Verification Confidence, (c) Measured Classification Accuracy (ground-truth labeled trials only), and (d) Operational Verification Success Rate.',
      '4. Explicitly highlight insufficient sample counts, modality conflicts, spoof/liveness triggers, inconclusive states, or low signal quality when present in the context.',
      '5. NEVER grant/deny physical access or override RBAC authorization.',
      '6. Format EVERY response using these exact 3 markdown sections:',
      '   ## Observed Facts & Telemetry',
      '   ## AI-Generated Hypotheses & Risk Assessment',
      '   ## Recommended Next Steps',
    ].join('\n');

    const safeContext = JSON.stringify(body.context || {}).slice(0, 9500);
    const historyText = (body.history || [])
      .slice(-6)
      .map((h) => `${h.role === 'user' ? 'Analyst' : 'AI Security Analyst'}: ${String(h.text).slice(0, 900)}`)
      .join('\n');

    const fullContents = [
      `Authorized Security Telemetry Context:\n${safeContext}`,
      historyText ? `Prior Investigation Thread:\n${historyText}` : '',
      `Request:\n${prompt}`,
    ]
      .filter(Boolean)
      .join('\n\n');

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: fullContents,
        config: {
          systemInstruction,
        },
      });

      const reply = response.text || '';
      if (!reply) {
        res.status(502).json({ error: 'empty_model_response', message: 'Gemini returned an empty response.' });
        return;
      }

      res.json({
        model: 'gemini-4-hydrogen',
        mode: body.mode || 'chat',
        reply,
        aiGenerated: true,
        disclaimer: 'Advisory AI analysis only — never treat AI output as guaranteed proof of identity.',
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Gemini API request failed.';
      res.status(502).json({ error: 'gemini_request_failed', message });
    }
  }
);

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const errObj = err as Error & { status?: number; code?: string };
  if (err instanceof VaultSecretError || errObj?.code === 'vault_secret_not_configured') {
    res.status(503).json({
      error: 'vault_secret_not_configured',
      message: 'BIOGUARD_VAULT_SECRET (>=32 chars) is not configured on the server.',
    });
    return;
  }
  const status = typeof errObj?.status === 'number' && errObj.status >= 400 && errObj.status < 600 ? errObj.status : 503;
  const code = typeof errObj?.code === 'string' ? errObj.code : 'backend_unavailable';
  console.error(`BioGuard X API request failed (${status} ${code}):`, errObj?.message || 'Unknown error');
  res.status(status).json({
    error: code,
    message:
      status === 503
        ? 'The backend could not complete this request. Check the Vercel function, vault secret, and Firestore configuration.'
        : errObj?.message || 'Request failed.',
  });
});

function registerProductionFrontend() {
  const publicDir = path.join(rootDir, 'public');
  app.use(express.static(publicDir));
  app.get('*', (_req: Request, res: Response) => {
    res.sendFile(path.join(publicDir, 'index.html'));
  });
}

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const publicDir = path.join(rootDir, 'public');
    // Serve local ML model weights & PWA icon assets during Vite dev middleware mode
    app.use('/models', express.static(path.join(publicDir, 'models'), { index: false }));
    for (const iconFile of [
      '/icon.svg',
      '/pwa-192x192.png',
      '/pwa-512x512.png',
      '/pwa-maskable-512x512.png',
      '/apple-touch-icon.png',
    ]) {
      app.get(iconFile, (_req: Request, res: Response) => {
        res.sendFile(path.join(publicDir, iconFile.slice(1)));
      });
    }

    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false, ws: false },
      plugins: [
        {
          name: 'bioguard-disable-hmr-client-ws',
          transform(code: string, id: string) {
            if (id.includes('vite/dist/client/client.mjs')) {
              return code.replace(
                /const transport = normalizeModuleRunnerTransport\(\(\(\) => \{[\s\S]*?\}\)\(\)\);/,
                'const transport = normalizeModuleRunnerTransport({ connect() {}, disconnect() {}, send() {} });'
              );
            }
            return null;
          },
        },
      ],
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    registerProductionFrontend();
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`BioGuard X server listening on http://0.0.0.0:${PORT}`);
  });
}

if (process.env.VERCEL === '1') {
  registerProductionFrontend();
} else if (process.env.BIOGUARD_SKIP_LISTEN !== '1') {
  void startServer();
}

export default app;
