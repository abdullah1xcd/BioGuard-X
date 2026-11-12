import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import { GoogleGenAI } from '@google/genai';
import firebaseConfigJson from './firebase-applet-config.json' with { type: 'json' };

interface FirebaseConfig {
  projectId: string;
  firestoreDatabaseId: string;
  apiKey: string;
  authDomain: string;
}

const rootDir = process.cwd();
const firebaseConfig = firebaseConfigJson as FirebaseConfig;

const FEATURE_VERSION = 'v1.1-classical-liveness';
const BOOTSTRAPPED_ADMIN_EMAIL = 'abdullahmohamedharoon8@gmail.com';
const PORT = Number(process.env.PORT || 3000);

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
    'view_identities', 'perform_verification', 'view_analytics', 'view_audit_logs',
    'manage_alerts', 'use_ai_analyst',
  ],
  operator: [
    'view_identities', 'create_identity', 'edit_identity', 'perform_verification',
    'view_analytics', 'use_ai_analyst',
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
    fingerprint?: number[][];
  };
}

interface ModalityQualityInput {
  face?: {
    contrastStd?: number;
    sharpness?: number;
    spoofRiskFlag?: boolean;
    isLiveCapture?: boolean;
    frameMotionScore?: number;
    captureSource?: string;
  };
  voice?: {
    durationSec?: number;
    meanRms?: number;
    meanZcr?: number;
    speechSegments?: number;
    clippingRatio?: number;
    dynamicRangeDb?: number;
    captureSource?: string;
  };
  fingerprint?: {
    ridgeDensity?: number;
    minutiaeHeuristicCount?: number;
    validPrint?: boolean;
    captureSource?: string;
  };
}

// AES-256-GCM encrypted biometric templates stored durably in Firestore.
// Vercel function filesystems are ephemeral; never persist biometric templates on local disk.
function getVaultKey(): Buffer {
  const envSecret = process.env.BIOGUARD_VAULT_SECRET?.trim();
  if (!envSecret || envSecret.length < 32) {
    throw new Error('BIOGUARD_VAULT_SECRET must be configured (at least 32 characters).');
  }
  return crypto.scryptSync(envSecret, 'bioguard-x-salt-v1', 32);
}

function encryptVaultMap(map: Record<string, VaultEntry>): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getVaultKey(), iv);
  const plaintext = Buffer.from(JSON.stringify(map), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  });
}

function decryptVaultMap(raw: string): Record<string, VaultEntry> {
  const parsed = JSON.parse(raw) as { iv: string; tag: string; ciphertext: string };
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    getVaultKey(),
    Buffer.from(parsed.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
  const dec = Buffer.concat([
    decipher.update(Buffer.from(parsed.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(dec.toString('utf8')) as Record<string, VaultEntry>;
}

async function loadVault(idToken: string): Promise<Record<string, VaultEntry>> {
  const url = `${firestoreDocUrl('biometric_vault')}?pageSize=1000`;
  const response = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` } });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Firestore vault read failed (${response.status}): ${detail.slice(0, 300)}`);
  }
  const payload = await response.json() as {
    documents?: Array<{ fields?: { encryptedPayload?: { stringValue?: string } } }>;
  };
  const vault: Record<string, VaultEntry> = {};
  for (const document of payload.documents || []) {
    const encryptedPayload = document.fields?.encryptedPayload?.stringValue;
    if (!encryptedPayload) continue;
    Object.assign(vault, decryptVaultMap(encryptedPayload));
  }
  return vault;
}

async function saveVault(
  map: Record<string, VaultEntry>,
  idToken: string,
  previous: Record<string, VaultEntry> = {}
): Promise<void> {
  const headers = {
    Authorization: `Bearer ${idToken}`,
    'Content-Type': 'application/json',
  };
  for (const [identityRef, entry] of Object.entries(map)) {
    if (previous[identityRef] && JSON.stringify(previous[identityRef]) === JSON.stringify(entry)) continue;
    const url = firestoreDocUrl(`biometric_vault/${encodeURIComponent(identityRef)}`);
    const response = await fetch(url, {
      method: 'PATCH',
      headers,
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
  for (const identityRef of Object.keys(previous)) {
    if (map[identityRef]) continue;
    const url = firestoreDocUrl(`biometric_vault/${encodeURIComponent(identityRef)}`);
    const response = await fetch(url, { method: 'DELETE', headers });
    if (!response.ok && response.status !== 404) {
      const detail = await response.text().catch(() => '');
      throw new Error(`Firestore vault delete failed (${response.status}): ${detail.slice(0, 300)}`);
    }
  }
}

// Classical Biometric Math (server-side authoritative matching)
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

function cosineSimilarity(a: number[], b: number[]): number {
  if (!a.length || a.length !== b.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  if (!denom) return 0;
  return Math.max(0, Math.min(1, (dot / denom + 1) / 2));
}

function scoreAgainstRefs(probe: number[], refs: number[][]): number {
  if (!refs.length) return 0;
  let best = 0;
  let total = 0;
  for (const r of refs) {
    const s = cosineSimilarity(probe, r);
    if (s > best) best = s;
    total += s;
  }
  return Number((0.6 * best + 0.4 * (total / refs.length)).toFixed(4));
}

function earlyFusionVector(faceVec: number[], voiceVec: number[]): number[] {
  const wf = 1 / Math.sqrt(faceVec.length || 1);
  const wv = 1 / Math.sqrt(voiceVec.length || 1);
  return l2Normalize([...faceVec.map((v) => v * wf), ...voiceVec.map((v) => v * wv)]);
}

function validateVector(vec: unknown, expectedDim: number): number[] | null {
  if (!Array.isArray(vec) || vec.length !== expectedDim) return null;
  const clean: number[] = [];
  for (const item of vec) {
    if (typeof item !== 'number' || !Number.isFinite(item)) return null;
    clean.push(item);
  }
  const norm = Math.sqrt(clean.reduce((a, b) => a + b * b, 0));
  if (norm < 1e-6 || vectorStd(clean) < 1e-4) return null;
  return l2Normalize(clean);
}

// Quality & Anti-Spoofing Gate (Rejects blank/flat/silent/invalid uploads)
function evaluateModalityQuality(
  modalities: { face: boolean; voice: boolean; fingerprint: boolean },
  quality: ModalityQualityInput | undefined
): { ok: boolean; errors: string[]; warnings: string[]; checks: Record<string, string> } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const checks: Record<string, string> = {};

  if (modalities.face) {
    const fq = quality?.face;
    if (fq) {
      if (typeof fq.contrastStd === 'number' && fq.contrastStd < 6) {
        errors.push(`Face image rejected: contrast too low (${fq.contrastStd}). Upload a clear, illuminated face image.`);
      } else if (typeof fq.sharpness === 'number' && fq.sharpness < 3) {
        errors.push(`Face image rejected: image is too blurry or uniform (sharpness=${fq.sharpness}).`);
      } else {
        checks.face = fq.isLiveCapture ? 'Live webcam quality passed' : 'Image quality passed';
      }
      if (fq.spoofRiskFlag) {
        warnings.push('Face sample exhibits flat texture / low Laplacian detail (spoof risk flag).');
      }
    } else {
      checks.face = 'Vector entropy verified';
    }
  }

  if (modalities.voice) {
    const vq = quality?.voice;
    if (vq) {
      if (typeof vq.durationSec === 'number' && vq.durationSec < 0.35) {
        errors.push(`Voice sample rejected: audio duration too short (${vq.durationSec}s). Record at least 0.5s.`);
      } else if (typeof vq.meanRms === 'number' && vq.meanRms < 0.004) {
        errors.push('Voice sample rejected: audio appears silent or below microphone threshold.');
      } else if (typeof vq.speechSegments === 'number' && vq.speechSegments < 1) {
        errors.push('Voice sample rejected: no active speech segments detected.');
      } else {
        checks.voice = `Acoustic quality passed (${vq.speechSegments ?? 1} speech segment(s))`;
      }
      if (typeof vq.clippingRatio === 'number' && vq.clippingRatio > 0.15) {
        warnings.push('Voice sample shows heavy clipping (possible loudspeaker playback).');
      }
    } else {
      checks.voice = 'Vector entropy verified';
    }
  }

  if (modalities.fingerprint) {
    const fpq = quality?.fingerprint;
    if (fpq) {
      if (typeof fpq.ridgeDensity === 'number' && (fpq.ridgeDensity < 6 || fpq.ridgeDensity > 94)) {
        errors.push(`Fingerprint rejected: abnormal ridge density (${fpq.ridgeDensity}%).`);
      } else if (typeof fpq.minutiaeHeuristicCount === 'number' && fpq.minutiaeHeuristicCount < 4) {
        errors.push('Fingerprint rejected: insufficient ridge/minutiae structure detected.');
      } else {
        checks.fingerprint = `Ridge quality passed (${fpq.minutiaeHeuristicCount ?? 'OK'} minutiae points)`;
      }
    } else {
      checks.fingerprint = 'Vector entropy verified';
    }
  }

  return { ok: errors.length === 0, errors, warnings, checks };
}

// Liveness & Anti-Spoofing Evaluator
function evaluateLiveness(
  modalities: { face: boolean; voice: boolean; fingerprint: boolean },
  quality: ModalityQualityInput | undefined
): { passed: boolean; score: number; spoofSignals: string[]; checks: string[] } {
  let score = 0.86;
  const spoofSignals: string[] = [];
  const checks: string[] = [];

  if (modalities.face && quality?.face) {
    const fq = quality.face;
    if (fq.isLiveCapture && typeof fq.frameMotionScore === 'number') {
      if (fq.frameMotionScore >= 0.008) {
        score = Math.min(0.98, score + 0.08);
        checks.push(`Live webcam motion verified (delta=${fq.frameMotionScore})`);
      } else {
        score -= 0.36;
        spoofSignals.push(`Static webcam feed detected (motion=${fq.frameMotionScore}; possible photo/screen spoof)`);
      }
    } else {
      checks.push('Static face upload checked for texture/sharpness');
    }
    if (fq.spoofRiskFlag) {
      score -= 0.42;
      spoofSignals.push('Low facial high-frequency detail (possible printed photo or screen replay)');
    }
  }

  if (modalities.voice && quality?.voice) {
    const vq = quality.voice;
    if (typeof vq.clippingRatio === 'number' && vq.clippingRatio > 0.15) {
      score -= 0.35;
      spoofSignals.push(`Audio clipping (${(vq.clippingRatio * 100).toFixed(1)}%) indicates possible speaker replay`);
    } else if (typeof vq.dynamicRangeDb === 'number' && vq.dynamicRangeDb < 6) {
      score -= 0.30;
      spoofSignals.push(`Low acoustic dynamic range (${vq.dynamicRangeDb} dB)`);
    } else {
      checks.push('Voice spectral dynamic range within natural bounds');
    }
  }

  if (modalities.fingerprint && quality?.fingerprint) {
    const fpq = quality.fingerprint;
    if (fpq.validPrint === false) {
      score -= 0.40;
      spoofSignals.push('Fingerprint ridge-to-valley ratio outside natural bounds');
    } else {
      checks.push('Fingerprint ridge continuity verified');
    }
  }

  const clamped = Number(Math.max(0.05, Math.min(0.99, score)).toFixed(2));
  return {
    passed: clamped >= 0.50 && spoofSignals.length === 0,
    score: clamped,
    spoofSignals,
    checks,
  };
}

// Behavioral & Verification Risk Engine
const verificationHistory = new Map<string, Array<{ ts: number; outcome: string; spoof: boolean }>>();

function computeRiskAssessment(params: {
  identityRef: string;
  pipeline: string;
  enrolledModalitiesCount: number;
  liveness: { passed: boolean; score: number; spoofSignals: string[] };
  preliminaryScore: number;
  baseThreshold: number;
}) {
  const now = Date.now();
  const windowMs = 15 * 60_000;
  const recent = (verificationHistory.get(params.identityRef) || []).filter((e) => now - e.ts < windowMs);
  const recentFailures = recent.filter((e) => e.outcome === 'no_match').length;
  const recentSpoofs = recent.filter((e) => e.spoof).length;

  let riskScore = 10;
  const factors: string[] = [];

  if (recentFailures > 0) {
    const add = Math.min(45, recentFailures * 16);
    riskScore += add;
    factors.push(`${recentFailures} failed verification attempt(s) in last 15 min (+${add})`);
  }
  if (recentSpoofs > 0) {
    riskScore += 20;
    factors.push(`Prior spoofing/liveness alert recorded in session window (+20)`);
  }
  if (!params.liveness.passed) {
    riskScore += 45;
    factors.push(`Liveness check failed: ${params.liveness.spoofSignals[0] || 'spoof signal'} (+45)`);
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
    factors.push('No anomalous attempt velocity or liveness anomalies detected');
  }

  return { riskScore, riskLevel, factors, recentFailures };
}

function recordRiskEvent(identityRef: string, outcome: string, spoof: boolean) {
  const now = Date.now();
  const recent = (verificationHistory.get(identityRef) || []).filter((e) => now - e.ts < 15 * 60_000);
  recent.push({ ts: now, outcome, spoof });
  verificationHistory.set(identityRef, recent);
}

// Firestore REST Helper using caller's verified Firebase ID Token
function firestoreDocUrl(docPath: string): string {
  const dbId = encodeURIComponent(firebaseConfig.firestoreDatabaseId);
  return `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/${dbId}/documents/${docPath}`;
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
    });
    if (!res.ok) return { role: 'viewer', status: 'active' };
    const docJson = (await res.json()) as {
      fields?: {
        role?: { stringValue?: string };
        status?: { stringValue?: string };
      };
    };
    const rawRole = docJson.fields?.role?.stringValue as Role | undefined;
    const rawStatus = docJson.fields?.status?.stringValue || 'active';
    const validRole: Role = rawRole && rawRole in ROLE_CAPABILITIES ? rawRole : 'viewer';
    return { role: validRole, status: rawStatus };
  } catch {
    return { role: 'viewer', status: 'active' };
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

// Sliding Window Rate Limiter
const rateBuckets = new Map<string, number[]>();
function rateLimit(maxRequests: number, windowMs: number) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const key = `${req.path}:${req.auth?.uid || req.ip || 'anon'}`;
    const now = Date.now();
    const hits = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
    if (hits.length >= maxRequests) {
      res.status(429).json({
        error: 'rate_limit_exceeded',
        message: 'Too many requests in the current window. Please wait briefly and retry.',
      });
      return;
    }
    hits.push(now);
    rateBuckets.set(key, hits);
    next();
  };
}

// Firebase Auth + Server-Side Role Middleware
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
    const lookup = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseConfig.apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken }),
    });
    if (!lookup.ok) throw new Error('Firebase rejected the ID token.');
    const lookupPayload = await lookup.json() as { users?: Array<{ localId: string; email?: string; emailVerified?: boolean }> };
    const firebaseUser = lookupPayload.users?.[0];
    if (!firebaseUser?.localId) throw new Error('Firebase user was not found for this ID token.');
    const decoded = {
      uid: firebaseUser.localId,
      email: firebaseUser.email,
      email_verified: firebaseUser.emailVerified === true,
    };
    if (!decoded.email_verified) {
      res.status(403).json({ error: 'email_not_verified', message: 'Verified Google account email is required.' });
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
    const message = err instanceof Error ? err.message : 'Token verification failed.';
    res.status(401).json({ error: 'invalid_credentials', message });
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

const app = express();
app.use(express.json({ limit: '2mb' }));

const asyncHandler = (
  handler: (req: AuthedRequest, res: Response) => Promise<void>
) => (req: Request, res: Response, next: NextFunction) => {
  Promise.resolve(handler(req as AuthedRequest, res)).catch(next);
};



// 1. Health Endpoint
app.get('/api/v1/health', (_req: Request, res: Response) => {
  const vaultConfigured = Boolean(process.env.BIOGUARD_VAULT_SECRET && process.env.BIOGUARD_VAULT_SECRET.trim().length >= 32);
  res.status(vaultConfigured ? 200 : 503).json({
    status: vaultConfigured ? 'ok' : 'degraded',
    service: 'bioguard-x-api',
    feature_version: FEATURE_VERSION,
    vault_ready: vaultConfigured,
    storage: 'firestore-encrypted-templates',
    encrypted_identities: null,
    firebase_project: firebaseConfig.projectId,
    firestore_database: firebaseConfig.firestoreDatabaseId,
    gemini_configured: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

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
    const faceVec = samples.face !== undefined ? validateVector(samples.face, 208) : null;
    const voiceVec = samples.voice !== undefined ? validateVector(samples.voice, 44) : null;
    const fpVec = samples.fingerprint !== undefined ? validateVector(samples.fingerprint, 130) : null;

    if (samples.face !== undefined && !faceVec) {
      res.status(400).json({ error: 'invalid_face_sample', message: 'Face sample failed validation (must be valid non-uniform 208-D vector).', requestId });
      return;
    }
    if (samples.voice !== undefined && !voiceVec) {
      res.status(400).json({ error: 'invalid_voice_sample', message: 'Voice sample failed validation (must be valid non-uniform 44-D vector).', requestId });
      return;
    }
    if (samples.fingerprint !== undefined && !fpVec) {
      res.status(400).json({ error: 'invalid_fingerprint_sample', message: 'Fingerprint sample failed validation (must be valid non-uniform 130-D vector).', requestId });
      return;
    }
    if (!faceVec && !voiceVec && !fpVec) {
      res.status(400).json({ error: 'no_modalities_provided', message: 'At least one valid biometric modality sample is required.', requestId });
      return;
    }

    const qualityReport = evaluateModalityQuality(
      { face: Boolean(faceVec), voice: Boolean(voiceVec), fingerprint: Boolean(fpVec) },
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

    const previousVault = await loadVault(req.auth!.idToken);
    const vault = { ...previousVault };
    const existing = vault[identityRef];
    const now = new Date().toISOString();
    const entry: VaultEntry = existing || {
      identityRef,
      featureVersion: FEATURE_VERSION,
      enrolledAt: now,
      updatedAt: now,
      modalities: {},
    };
    entry.updatedAt = now;
    entry.featureVersion = FEATURE_VERSION;

    if (faceVec) entry.modalities.face = [...(entry.modalities.face || []).slice(-4), faceVec];
    if (voiceVec) entry.modalities.voice = [...(entry.modalities.voice || []).slice(-4), voiceVec];
    if (fpVec) entry.modalities.fingerprint = [...(entry.modalities.fingerprint || []).slice(-4), fpVec];

    vault[identityRef] = entry;
    await saveVault(vault, req.auth!.idToken, previousVault);

    const registeredModalities = Object.keys(entry.modalities).filter(
      (m) => (entry.modalities[m as keyof typeof entry.modalities]?.length || 0) > 0
    );

    res.status(201).json({
      status: 'enrolled',
      identityRef,
      registeredModalities,
      featureVersion: FEATURE_VERSION,
      qualityChecks: qualityReport.checks,
      qualityWarnings: qualityReport.warnings,
      encryptedAt: now,
      requestId,
    });
  })
);

// 4. Multimodal Biometric Verification (Quality + Liveness + Fusion + Adaptive Risk Engine)
app.post(
  '/api/v1/verification/multimodal',
  requireAuth,
  requireCapability('perform_verification'),
  rateLimit(40, 60_000),
  asyncHandler(async (req: AuthedRequest, res: Response) => {
    const requestId = `ver_${crypto.randomUUID().slice(0, 12)}`;
    const body = req.body as {
      identityRef?: string;
      pipeline?: string;
      adaptiveEnabled?: boolean;
      thresholds?: Record<string, number>;
      samples?: { face?: unknown; voice?: unknown; fingerprint?: unknown };
      quality?: ModalityQualityInput;
    };

    const identityRef = String(body.identityRef || '').trim();
    const pipeline = String(body.pipeline || 'hierarchical').trim();
    const adaptiveEnabled = body.adaptiveEnabled !== false;
    if (!/^[a-zA-Z0-9_-]{2,64}$/.test(identityRef)) {
      res.status(400).json({ error: 'invalid_identity_ref', message: 'Valid identityRef is required.', requestId });
      return;
    }

    const vault = await loadVault(req.auth!.idToken);
    const entry = vault[identityRef];
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
    if (entry.featureVersion !== FEATURE_VERSION && entry.featureVersion !== 'v1.0-classical') {
      res.status(409).json({
        error: 'feature_version_mismatch',
        message: `Template version ${entry.featureVersion} is incompatible with ${FEATURE_VERSION}.`,
        outcome: 'not_evaluated',
        policy_decision: 'pending',
        requestId,
      });
      return;
    }

    const samples = body.samples || {};
    const faceVec = samples.face !== undefined ? validateVector(samples.face, 208) : null;
    const voiceVec = samples.voice !== undefined ? validateVector(samples.voice, 44) : null;
    const fpVec = samples.fingerprint !== undefined ? validateVector(samples.fingerprint, 130) : null;

    if ((samples.face !== undefined && !faceVec) || (samples.voice !== undefined && !voiceVec) || (samples.fingerprint !== undefined && !fpVec)) {
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
      { face: Boolean(faceVec), voice: Boolean(voiceVec), fingerprint: Boolean(fpVec) },
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

    const refsFace = entry.modalities.face || [];
    const refsVoice = entry.modalities.voice || [];
    const refsFp = entry.modalities.fingerprint || [];
    const enrolledCount = [refsFace.length > 0, refsVoice.length > 0, refsFp.length > 0].filter(Boolean).length;

    const faceScore = faceVec && refsFace.length ? scoreAgainstRefs(faceVec, refsFace) : null;
    const voiceScore = voiceVec && refsVoice.length ? scoreAgainstRefs(voiceVec, refsVoice) : null;
    const fpScore = fpVec && refsFp.length ? scoreAgainstRefs(fpVec, refsFp) : null;

    const liveness = evaluateLiveness(
      { face: Boolean(faceVec), voice: Boolean(voiceVec), fingerprint: Boolean(fpVec) },
      body.quality
    );

    const thr = {
      face: body.thresholds?.face ?? 0.72,
      voice: body.thresholds?.voice ?? 0.70,
      fingerprint: body.thresholds?.fingerprint ?? 0.72,
      early: body.thresholds?.early ?? 0.73,
      threeModal: body.thresholds?.threeModal ?? 0.74,
    };

    let outcome: 'match' | 'no_match' | 'not_evaluated' = 'not_evaluated';
    let finalScore = 0;
    let baseThreshold = 0.72;
    let reasonCode = 'ok';
    const modalitiesEvaluated: string[] = [];
    const details: Record<string, unknown> = {};

    if (pipeline === 'face' || pipeline === 'face_only') {
      if (faceScore === null) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Face sample and enrolled face template are required.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('face');
      finalScore = faceScore;
      baseThreshold = thr.face;
      details.faceScore = faceScore;
    } else if (pipeline === 'voice' || pipeline === 'voice_only') {
      if (voiceScore === null) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Voice sample and enrolled voice template are required.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('voice');
      finalScore = voiceScore;
      baseThreshold = thr.voice;
      details.voiceScore = voiceScore;
    } else if (pipeline === 'fingerprint' || pipeline === 'fingerprint_only') {
      if (fpScore === null) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Fingerprint sample and enrolled fingerprint template are required.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('fingerprint');
      finalScore = fpScore;
      baseThreshold = thr.fingerprint;
      details.fpScore = fpScore;
    } else if (pipeline === 'face_fingerprint') {
      if (faceScore === null || fpScore === null) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Face and Fingerprint samples + templates required.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('face', 'fingerprint');
      finalScore = Number((0.55 * faceScore + 0.45 * fpScore).toFixed(4));
      baseThreshold = Number(((thr.face + thr.fingerprint) / 2).toFixed(4));
      details.faceScore = faceScore;
      details.fpScore = fpScore;
    } else if (pipeline === 'voice_fingerprint') {
      if (voiceScore === null || fpScore === null) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Voice and Fingerprint samples + templates required.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('voice', 'fingerprint');
      finalScore = Number((0.50 * voiceScore + 0.50 * fpScore).toFixed(4));
      baseThreshold = Number(((thr.voice + thr.fingerprint) / 2).toFixed(4));
      details.voiceScore = voiceScore;
      details.fpScore = fpScore;
    } else if (pipeline === 'three_modal') {
      if (faceScore === null || voiceScore === null || fpScore === null) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Face, Voice, and Fingerprint samples + enrolled templates are required for three-modality fusion.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('face', 'voice', 'fingerprint');
      finalScore = Number((0.45 * faceScore + 0.30 * voiceScore + 0.25 * fpScore).toFixed(4));
      baseThreshold = thr.threeModal;
      details.faceScore = faceScore;
      details.voiceScore = voiceScore;
      details.fpScore = fpScore;
    } else if (pipeline === 'early_fusion' || pipeline === 'face_voice') {
      if (faceScore === null || voiceScore === null || !faceVec || !voiceVec) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Face and Voice samples + templates required.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('face', 'voice');
      const probeEarly = earlyFusionVector(faceVec, voiceVec);
      const refEarly = refsFace.map((rf, i) => earlyFusionVector(rf, refsVoice[i % refsVoice.length]));
      finalScore = scoreAgainstRefs(probeEarly, refEarly);
      baseThreshold = thr.early;
      details.faceScore = faceScore;
      details.voiceScore = voiceScore;
    } else if (pipeline === 'hierarchical') {
      if (faceScore === null || !faceVec) {
        res.status(422).json({ error: 'missing_template_or_sample', message: 'Hierarchical verification requires a Face sample and enrolled Face template.', outcome: 'not_evaluated', policy_decision: 'pending', requestId });
        return;
      }
      modalitiesEvaluated.push('face');
      const highGate = Math.min(0.95, thr.face + 0.09);
      const lowGate = Math.max(0.35, thr.face - 0.14);
      details.faceScore = faceScore;

      if (faceScore >= highGate) {
        finalScore = faceScore;
        baseThreshold = highGate;
        reasonCode = 'hierarchical_stage1_face_match';
        details.stage = 'Stage 1 Fast-Match';
      } else if (faceScore <= lowGate) {
        finalScore = faceScore;
        baseThreshold = lowGate;
        reasonCode = 'hierarchical_stage1_face_reject';
        details.stage = 'Stage 1 Fast-No-Match';
      } else if (voiceScore !== null && voiceVec && refsVoice.length > 0) {
        modalitiesEvaluated.push('voice');
        const probeEarly = earlyFusionVector(faceVec, voiceVec);
        const refEarly = refsFace.map((rf, i) => earlyFusionVector(rf, refsVoice[i % refsVoice.length]));
        finalScore = scoreAgainstRefs(probeEarly, refEarly);
        baseThreshold = thr.early;
        details.voiceScore = voiceScore;
        details.stage = 'Stage 2 Early Fusion Escalation';
      } else {
        finalScore = faceScore;
        baseThreshold = thr.face;
        reasonCode = 'hierarchical_uncertain_voice_required';
        details.stage = 'Uncertain band — voice factor required';
      }
    } else {
      res.status(400).json({ error: 'unsupported_modality', message: `Unsupported pipeline "${pipeline}".`, outcome: 'not_evaluated', policy_decision: 'pending', requestId });
      return;
    }

    // Risk & Adaptive Verification Evaluation
    const risk = computeRiskAssessment({
      identityRef,
      pipeline,
      enrolledModalitiesCount: enrolledCount,
      liveness,
      preliminaryScore: finalScore,
      baseThreshold,
    });

    const isSingleModality = ['face', 'face_only', 'voice', 'voice_only', 'fingerprint', 'fingerprint_only'].includes(pipeline);
    let effectiveThreshold = baseThreshold;
    let adaptiveApplied = false;
    let adaptiveReason = '';

    if (adaptiveEnabled && risk.riskScore >= 50) {
      adaptiveApplied = true;
      if (isSingleModality && enrolledCount >= 2) {
        outcome = 'not_evaluated';
        reasonCode = 'adaptive_mfa_escalation_required';
        adaptiveReason = `Risk score ${risk.riskScore}/100 requires multimodal verification instead of single-factor.`;
      } else {
        effectiveThreshold = Number(Math.min(0.95, baseThreshold + 0.05).toFixed(4));
        adaptiveReason = `Threshold tightened by +0.05 (from ${baseThreshold} to ${effectiveThreshold}) due to ${risk.riskLevel} risk.`;
      }
    }

    if (reasonCode === 'hierarchical_uncertain_voice_required') {
      outcome = 'not_evaluated';
    } else if (outcome !== 'not_evaluated' || reasonCode !== 'adaptive_mfa_escalation_required') {
      if (!liveness.passed) {
        outcome = 'no_match';
        reasonCode = 'spoof_or_liveness_failed';
      } else if (reasonCode === 'hierarchical_stage1_face_reject') {
        outcome = 'no_match';
      } else {
        outcome = finalScore >= effectiveThreshold ? 'match' : 'no_match';
        if (reasonCode === 'ok' || reasonCode === 'hierarchical_stage1_face_match') {
          reasonCode = outcome === 'match' ? `${pipeline}_match` : `${pipeline}_below_threshold`;
        }
      }
    }

    recordRiskEvent(identityRef, outcome, !liveness.passed);

    details.qualityChecks = qualityReport.checks;
    details.liveness = liveness;
    details.risk = {
      score: risk.riskScore,
      level: risk.riskLevel,
      factors: risk.factors,
    };
    if (adaptiveApplied) {
      details.adaptive = {
        applied: true,
        baseThreshold,
        effectiveThreshold,
        reason: adaptiveReason,
      };
    }

    res.json({
      status: 'ok',
      identityRef,
      pipeline,
      modalitiesEvaluated,
      outcome,
      policy_decision: 'pending',
      reasonCode,
      score: finalScore,
      threshold: effectiveThreshold,
      baseThreshold,
      adaptiveApplied,
      liveness,
      risk: {
        score: risk.riskScore,
        level: risk.riskLevel,
        factors: risk.factors,
      },
      details,
      featureVersion: FEATURE_VERSION,
      requestId,
    });
  })
);

// 5. Vault Identity Status & Admin Deletion
app.get('/api/v1/identities/:identityRef/vault', requireAuth, requireCapability('view_identities'), asyncHandler(async (req: AuthedRequest, res: Response) => {
  const identityRef = String(req.params.identityRef || '');
  const vault = await loadVault(req.auth!.idToken);
  const entry = vault[identityRef];
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
  const previousVault = await loadVault(req.auth!.idToken);
  const vault = { ...previousVault };
  if (!vault[identityRef]) {
    res.status(404).json({ error: 'not_found', message: 'Identity not present in biometric vault.' });
    return;
  }
  delete vault[identityRef];
  await saveVault(vault, req.auth!.idToken, previousVault);
  res.json({ status: 'deleted_from_vault', identityRef });
}));

// 6. Server-Verified Admin Role & Status Management
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

// 7. AI Security Analyst (Server-Side Gemini API Only)
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
      'You are the BioGuard X AI Security Analyst.',
      `Current authenticated operator role: ${req.auth!.role}.`,
      `Analysis Mode: ${body.mode || 'chat'}.`,
      'Non-negotiable operational rules:',
      '1. NEVER present AI-generated risk scores or analysis as guaranteed proof of identity.',
      '2. NEVER invent verification outcomes, similarity percentages, accuracy benchmarks, or unseen incidents.',
      '3. NEVER grant or deny physical access or override RBAC authorization.',
      '4. Always ground explanations in the provided non-biometric verification metadata, liveness signals, risk factors, security alerts, and audit records.',
      '5. Provide concise, actionable security next steps (e.g., requesting secondary modality, opening an alert investigation, reviewing threshold settings, or approving deletion requests).',
    ].join('\n');

    const safeContext = JSON.stringify(body.context || {}).slice(0, 7500);
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
  console.error('BioGuard X API request failed:', err);
  res.status(503).json({
    error: 'backend_unavailable',
    message: 'The backend could not complete this request. Check the Vercel function and Firestore configuration.',
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.join(rootDir, 'public');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`BioGuard X server listening on http://0.0.0.0:${PORT}`);
  });
}

if (process.env.VERCEL !== '1') {
  void startServer();
}

export default app;
