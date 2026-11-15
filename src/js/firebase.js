import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  signOut,
  onAuthStateChanged,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDoc,
  getDocFromServer,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  collection,
  query,
  orderBy,
  limit,
  onSnapshot,
  serverTimestamp,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: 'select_account' });

export const OperationType = {
  CREATE: 'create',
  UPDATE: 'update',
  DELETE: 'delete',
  LIST: 'list',
  GET: 'get',
  WRITE: 'write',
};

const fsTelemetry = {
  reads: 0,
  writes: 0,
  errors: 0,
  totalLatencyMs: 0,
  opsCount: 0,
  lastOpMs: null,
};

function trackFsOp(kind, t0, ok = true) {
  const dt = Number((performance.now() - t0).toFixed(1));
  fsTelemetry.opsCount++;
  fsTelemetry.totalLatencyMs += dt;
  fsTelemetry.lastOpMs = dt;
  if (kind === 'read') fsTelemetry.reads++;
  else fsTelemetry.writes++;
  if (!ok) fsTelemetry.errors++;
}

export function getFirestoreTelemetry() {
  return {
    ...fsTelemetry,
    avgLatencyMs: fsTelemetry.opsCount
      ? Number((fsTelemetry.totalLatencyMs / fsTelemetry.opsCount).toFixed(1))
      : null,
  };
}

export function handleFirestoreError(error, operationType, path, operationStage = null) {
  const errInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid || null,
      email: auth.currentUser?.email || null,
      emailVerified: auth.currentUser?.emailVerified ?? null,
      isAnonymous: auth.currentUser?.isAnonymous ?? null,
      tenantId: auth.currentUser?.tenantId || null,
      providerInfo:
        auth.currentUser?.providerData?.map((p) => ({
          providerId: p.providerId,
          email: p.email,
        })) || [],
    },
    operationType,
    path,
  };
  const serialized = JSON.stringify(errInfo);
  console.error('Firestore Error:', serialized);
  const rawCode = String(error?.code || '');
  const httpStatus = rawCode === 'permission-denied' ? 403 : rawCode === 'unauthenticated' ? 401 : undefined;
  const wrapped = Object.assign(new Error(serialized, { cause: error }), {
    code: rawCode ? `firestore_${rawCode.replace(/[^a-zA-Z0-9_]/g, '_')}` : 'firestore_error',
    ...(httpStatus ? { status: httpStatus, httpStatus } : {}),
    operationStage: operationStage || error?.operationStage || operationType,
    operationType,
    path,
    isFirestoreError: true,
  });
  throw wrapped;
}

// Connection check on boot
export async function testFirestoreConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
    return { connected: true };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('the client is offline')) {
      return { connected: false, error: 'Firestore client is offline. Check Firebase configuration.' };
    }
    // Permission denied on /test/connection still proves server reachability
    return { connected: true };
  }
}

export async function resolveAuthRedirect() {
  try {
    const result = await getRedirectResult(auth);
    return result?.user || null;
  } catch (err) {
    console.warn('Google redirect sign-in returned error:', err?.message || err);
    throw err;
  }
}

export async function signInWithGoogle() {
  const isStandalone =
    typeof window !== 'undefined' &&
    (window.matchMedia?.('(display-mode: standalone)')?.matches === true || window.navigator?.standalone === true);
  if (isStandalone) {
    await signInWithRedirect(auth, googleProvider);
    return null;
  }
  try {
    const cred = await signInWithPopup(auth, googleProvider);
    return cred.user;
  } catch (err) {
    const code = err?.code || '';
    if (
      code === 'auth/popup-blocked' ||
      code === 'auth/operation-not-supported-in-this-environment' ||
      code === 'auth/cancelled-popup-request'
    ) {
      await signInWithRedirect(auth, googleProvider);
      return null;
    }
    throw err;
  }
}

export async function signOutUser() {
  await signOut(auth);
}

export function onAuthChanged(callback) {
  return onAuthStateChanged(auth, callback);
}

export async function getFreshIdToken() {
  if (!auth.currentUser) throw new Error('User is not authenticated.');
  return auth.currentUser.getIdToken();
}

function makeId(prefix) {
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${Date.now()}_${rand}`.replace(/[^a-zA-Z0-9_-]/g, '');
}

const BOOTSTRAPPED_ADMIN_EMAIL = 'abdullahmohamedharoon8@gmail.com';
const VALID_IDENTITY_RE = /^[a-zA-Z0-9_-]{2,64}$/;
const SUPPORTED_MODALITIES = new Set(['face', 'voice', 'fingerprint']);

function makeDiagnosticError(message, operationStage, code) {
  const err = new Error(message);
  err.operationStage = operationStage;
  err.code = code || operationStage;
  return err;
}

// Idempotent user provisioning & bootstrap admin self-healing in /users/{uid} and /admins/{uid}
export async function provisionUserProfile(fbUser) {
  if (!fbUser?.uid) {
    throw makeDiagnosticError('Authenticated user UID is missing.', 'user_profile_provisioning', 'missing_uid');
  }
  if (!fbUser.emailVerified) {
    throw makeDiagnosticError(
      'Verified Google email address is required before provisioning profile.',
      'user_profile_provisioning',
      'email_not_verified'
    );
  }

  const userPath = `users/${fbUser.uid}`;
  const ref = doc(db, 'users', fbUser.uid);
  const adminRef = doc(db, 'admins', fbUser.uid);
  const isBootstrap =
    fbUser.emailVerified === true &&
    String(fbUser.email || '').trim().toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL;

  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      const initialRole = isBootstrap ? 'super_admin' : 'operator';
      const fallbackEmail = `${fbUser.uid}@users.local`;
      const payload = {
        uid: fbUser.uid,
        displayName: (fbUser.displayName || fbUser.email || 'Operator').slice(0, 120),
        email: (fbUser.email || fallbackEmail).slice(0, 180),
        photoURL: (fbUser.photoURL || '').slice(0, 500),
        role: initialRole,
        status: 'active',
        theme: 'dark',
        createdAt: serverTimestamp(),
        lastLoginAt: serverTimestamp(),
      };
      await setDoc(ref, payload);
      if (isBootstrap) {
        const adminSnap = await getDoc(adminRef);
        if (!adminSnap.exists()) {
          await setDoc(adminRef, {
            uid: fbUser.uid,
            role: 'super_admin',
            grantedBy: fbUser.uid,
            createdAt: serverTimestamp(),
          });
        }
      }
      const created = await getDoc(ref);
      return created.data();
    } else {
      const existingData = snap.data();
      const updates = {
        displayName: (fbUser.displayName || existingData.displayName || 'Operator').slice(0, 120),
        photoURL: (fbUser.photoURL || existingData.photoURL || '').slice(0, 500),
        lastLoginAt: serverTimestamp(),
      };
      // Never downgrade existing admin privileges; heal bootstrap admin only if role/status is incomplete
      if (isBootstrap) {
        if (existingData.role !== 'super_admin') updates.role = 'super_admin';
        if (existingData.status !== 'active') updates.status = 'active';
      }
      await updateDoc(ref, updates);
      if (isBootstrap) {
        const adminSnap = await getDoc(adminRef);
        if (!adminSnap.exists()) {
          await setDoc(adminRef, {
            uid: fbUser.uid,
            role: 'super_admin',
            grantedBy: fbUser.uid,
            createdAt: serverTimestamp(),
          });
        }
      }
      const updated = await getDoc(ref);
      return updated.data();
    }
  } catch (err) {
    if (err?.operationStage) throw err;
    handleFirestoreError(err, OperationType.WRITE, userPath, 'user_profile_provisioning');
  }
}

export async function updateOwnPreferences({ displayName, theme }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}`;
  try {
    const updates = { lastLoginAt: serverTimestamp() };
    if (displayName) updates.displayName = displayName.slice(0, 120);
    if (theme === 'dark' || theme === 'light') updates.theme = theme;
    await updateDoc(doc(db, 'users', uid), updates);
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function listUsersForAdmin() {
  try {
    const snap = await getDocs(query(collection(db, 'users'), limit(100)));
    return snap.docs.map((d) => d.data());
  } catch (err) {
    handleFirestoreError(err, OperationType.LIST, 'users');
  }
}

// Identities Metadata (NO vectors stored here; isolated per Google UID)
export async function saveIdentityMetadata({ identityRef, displayName, registeredModalities, featureVersion }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw makeDiagnosticError('Not signed in.', 'identity_enrollment', 'unauthenticated');
  const cleanRef = String(identityRef || '').trim();
  if (!VALID_IDENTITY_RE.test(cleanRef)) {
    throw makeDiagnosticError(
      'Invalid identity reference ID (must be 2-64 alphanumeric, underscore, or hyphen characters).',
      'identity_enrollment',
      'invalid_identity_ref'
    );
  }
  const cleanName = String(displayName || '').trim().slice(0, 120);
  if (!cleanName) {
    throw makeDiagnosticError('Identity display name is required.', 'identity_enrollment', 'invalid_display_name');
  }
  const cleanModalities = Array.isArray(registeredModalities)
    ? [...new Set(registeredModalities.filter((m) => SUPPORTED_MODALITIES.has(m)))].slice(0, 3)
    : [];
  if (cleanModalities.length === 0) {
    throw makeDiagnosticError(
      'At least one supported biometric modality (face, voice, fingerprint) is required for enrollment.',
      'identity_enrollment',
      'invalid_modalities'
    );
  }

  const path = `users/${uid}/identities/${cleanRef}`;
  try {
    const ref = doc(db, 'users', uid, 'identities', cleanRef);
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, {
        identityId: cleanRef,
        identityRef: cleanRef,
        displayName: cleanName,
        status: 'active',
        registeredModalities: cleanModalities,
        featureVersion: String(featureVersion || 'v2.0-multimodal').slice(0, 32),
        consentRecorded: true,
        createdBy: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        displayName: cleanName,
        registeredModalities: cleanModalities,
        featureVersion: String(featureVersion || 'v2.0-multimodal').slice(0, 32),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (err) {
    if (err?.operationStage) throw err;
    handleFirestoreError(err, OperationType.WRITE, path, 'identity_enrollment');
  }
}

export async function updateIdentityStatusOrName(identityRef, updates) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/identities/${identityRef}`;
  try {
    await updateDoc(doc(db, 'users', uid, 'identities', identityRef), {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function deleteIdentityMetadata(identityRef) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/identities/${identityRef}`;
  try {
    await deleteDoc(doc(db, 'users', uid, 'identities', identityRef));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

export function subscribeIdentities(_role, uid, onData, onErr) {
  const path = `users/${uid}/identities`;
  const q = query(collection(db, 'users', uid, 'identities'), orderBy('updatedAt', 'desc'), limit(150));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => ({ ...d.data(), _docId: d.id }))),
    (err) => {
      if (onErr) onErr(err);
      else handleFirestoreError(err, OperationType.LIST, path);
    }
  );
}

// Verification Records (isolated per Google UID)
export async function recordVerificationMetadata({
  identityRef,
  modalities,
  pipeline,
  outcome,
  finalDecision,
  livenessStatus,
  datasetCategory,
  captureFailure = false,
  reasonCode,
  score,
  confidence,
  confidenceBand,
  conflictDetected,
  processingTimeMs,
  featureVersion,
  groundTruth = 'unlabeled',
  isTestProbe = false,
  modalityEvaluations,
  riskScore,
  riskLevel,
  livenessPassed,
  livenessScore,
  livenessDecision,
  challengeVerified,
  identityConfidence,
  sampleQualityScore,
  livenessConfidence,
  adaptiveApplied,
  subjectKey,
  partition,
  sampleHash,
  benchmarkBatchId,
  provenanceSignature,
}) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw makeDiagnosticError('Not signed in.', 'verification_record_validation', 'unauthenticated');

  const cleanIdentityRef = String(identityRef || '').trim();
  if (!VALID_IDENTITY_RE.test(cleanIdentityRef)) {
    throw makeDiagnosticError(
      'Verification record rejected: invalid identity reference (must be 2-64 alphanumeric, underscore, or hyphen characters).',
      'verification_record_validation',
      'invalid_identity_ref'
    );
  }

  const safeModalities = Array.isArray(modalities)
    ? [...new Set(modalities.filter((item) => SUPPORTED_MODALITIES.has(item)))].slice(0, 3)
    : [];
  if (safeModalities.length === 0) {
    throw makeDiagnosticError(
      'Verification record rejected: at least one supported modality (face, voice, or fingerprint) is required.',
      'verification_record_validation',
      'invalid_modalities'
    );
  }

  if (!['match', 'no_match', 'not_evaluated'].includes(outcome)) {
    throw makeDiagnosticError(
      `Verification record rejected: invalid outcome "${String(outcome)}".`,
      'verification_record_validation',
      'invalid_outcome'
    );
  }

  // Verify the referenced identity metadata exists, belongs to this workspace, and is active before creating a record
  const identityPath = `users/${uid}/identities/${cleanIdentityRef}`;
  try {
    const idSnap = await getDoc(doc(db, 'users', uid, 'identities', cleanIdentityRef));
    if (!idSnap.exists()) {
      throw makeDiagnosticError(
        `Identity metadata not found at "${identityPath}". Re-enroll identity metadata before verifying.`,
        'identity_lookup',
        'identity_metadata_missing'
      );
    }
    const idData = idSnap.data();
    if (idData.status !== 'active') {
      throw makeDiagnosticError(
        `Identity "${cleanIdentityRef}" is currently "${idData.status}" and cannot accept new verification records.`,
        'identity_lookup',
        'identity_inactive'
      );
    }
    if (idData.identityRef !== cleanIdentityRef) {
      throw makeDiagnosticError(
        `Identity metadata integrity mismatch at "${identityPath}" (document identityRef="${idData.identityRef}").`,
        'identity_lookup',
        'identity_ref_mismatch'
      );
    }
  } catch (err) {
    if (err?.operationStage) throw err;
    handleFirestoreError(err, OperationType.GET, identityPath, 'identity_lookup');
  }

  const verificationId = makeId('ver');
  const path = `users/${uid}/verification_records/${verificationId}`;
  const t0 = performance.now();
  let debugSummary = null;
  try {
    // Build a Firestore-rules-safe record. Matcher telemetry can contain NaN/Infinity
    // when a modality is unavailable; those values must never be sent to Firestore.
    const safeOutcome = outcome;
    const safeGroundTruth = ['genuine', 'impostor', 'unlabeled'].includes(groundTruth) ? groundTruth : 'unlabeled';
    const derivedDatasetCategory = ['operational', 'synthetic_qa', 'benchmark_eval'].includes(datasetCategory)
      ? datasetCategory
      : isTestProbe
      ? 'synthetic_qa'
      : 'operational';
    const finiteClamp = (value, min, max, digits = 3) =>
      typeof value === 'number' && Number.isFinite(value)
        ? Number(Math.min(max, Math.max(min, value)).toFixed(digits))
        : null;
    const safeScore = finiteClamp(score, 0, 1, 4);
    const cleanPipeline = String(pipeline || 'hierarchical').trim().slice(0, 64) || 'hierarchical';
    const cleanReasonCode = String(reasonCode || 'evaluated').trim().slice(0, 80) || 'evaluated';
    const docData = {
      verificationId,
      identityRef: cleanIdentityRef,
      modalities: safeModalities,
      pipeline: cleanPipeline,
      outcome: safeOutcome,
      policyDecision: 'pending',
      reasonCode: cleanReasonCode,
      score: safeScore ?? 0,
      operatorUid: uid,
      datasetCategory: derivedDatasetCategory,
      captureFailure: Boolean(captureFailure),
      createdAt: serverTimestamp(),
    };
    if (['VERIFIED', 'REJECTED', 'INCONCLUSIVE'].includes(finalDecision)) {
      docData.finalDecision = finalDecision;
    }
    if (['LIVENESS PASSED', 'LIVENESS FAILED', 'INCONCLUSIVE', 'NOT SUPPORTED'].includes(livenessStatus)) {
      docData.livenessStatus = livenessStatus;
    }
    if (['PASSED', 'FAILED', 'INCONCLUSIVE'].includes(livenessDecision)) {
      docData.livenessDecision = livenessDecision;
    }
    if (typeof challengeVerified === 'boolean') {
      docData.challengeVerified = challengeVerified;
    }
    { const value = finiteClamp(riskScore, 0, 100, 0); if (value !== null) docData.riskScore = value; }
    if (['low', 'medium', 'high', 'critical'].includes(riskLevel)) docData.riskLevel = riskLevel;
    if (typeof livenessPassed === 'boolean') docData.livenessPassed = livenessPassed;
    { const value = finiteClamp(livenessScore, 0, 1, 2); if (value !== null) docData.livenessScore = value; }
    if (typeof adaptiveApplied === 'boolean') docData.adaptiveApplied = adaptiveApplied;
    docData.groundTruth = safeGroundTruth;
    if (typeof isTestProbe === 'boolean') docData.isTestProbe = isTestProbe;
    if (typeof processingTimeMs === 'number' && Number.isFinite(processingTimeMs)) {
      docData.processingTimeMs = Math.min(120000, Math.max(0, Number(processingTimeMs.toFixed(1))));
    }
    if (typeof confidence === 'number' && Number.isFinite(confidence)) {
      docData.confidence = Math.min(1, Math.max(0, Number(confidence.toFixed(3))));
    }
    if (typeof identityConfidence === 'number' && Number.isFinite(identityConfidence)) {
      docData.identityConfidence = Math.min(1, Math.max(0, Number(identityConfidence.toFixed(3))));
    }
    if (typeof sampleQualityScore === 'number' && Number.isFinite(sampleQualityScore)) {
      docData.sampleQualityScore = Math.min(1, Math.max(0, Number(sampleQualityScore.toFixed(3))));
    }
    if (typeof livenessConfidence === 'number' && Number.isFinite(livenessConfidence)) {
      docData.livenessConfidence = Math.min(1, Math.max(0, Number(livenessConfidence.toFixed(3))));
    }
    if (['high', 'moderate', 'low'].includes(confidenceBand)) docData.confidenceBand = confidenceBand;
    if (typeof conflictDetected === 'boolean') docData.conflictDetected = conflictDetected;
    if (typeof featureVersion === 'string' && featureVersion.trim().length > 0) {
      docData.featureVersion = featureVersion.trim().slice(0, 32);
    }
    if (typeof subjectKey === 'string' && subjectKey.trim().length > 0) {
      docData.subjectKey = subjectKey.trim().slice(0, 80);
    }
    if (partition === 'eval' || partition === 'unassigned') {
      docData.partition = partition;
    }
    if (typeof sampleHash === 'string' && sampleHash.trim().length > 0) {
      docData.sampleHash = sampleHash.trim().slice(0, 128);
    }
    if (typeof benchmarkBatchId === 'string' && benchmarkBatchId.trim().length > 0) {
      docData.benchmarkBatchId = benchmarkBatchId.trim().slice(0, 80);
    }
    if (typeof provenanceSignature === 'string' && provenanceSignature.trim().length > 0) {
      docData.provenanceSignature = provenanceSignature.trim().slice(0, 160);
    }

    if (modalityEvaluations?.face) {
      { const value = finiteClamp(modalityEvaluations.face.score, 0, 1, 4); if (value !== null) docData.faceScore = value; }
      { const value = finiteClamp(modalityEvaluations.face.qualityScore, 0, 100, 0); if (value !== null) docData.faceQuality = value; }
      if (['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(modalityEvaluations.face.status)) {
        docData.faceStatus = modalityEvaluations.face.status;
      }
    }
    if (modalityEvaluations?.voice) {
      { const value = finiteClamp(modalityEvaluations.voice.score, 0, 1, 4); if (value !== null) docData.voiceScore = value; }
      { const value = finiteClamp(modalityEvaluations.voice.qualityScore, 0, 100, 0); if (value !== null) docData.voiceQuality = value; }
      if (['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(modalityEvaluations.voice.status)) {
        docData.voiceStatus = modalityEvaluations.voice.status;
      }
    }
    if (modalityEvaluations?.fingerprint) {
      { const value = finiteClamp(modalityEvaluations.fingerprint.score, 0, 1, 4); if (value !== null) docData.fingerprintScore = value; }
      { const value = finiteClamp(modalityEvaluations.fingerprint.qualityScore, 0, 100, 0); if (value !== null) docData.fingerprintQuality = value; }
      if (['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(modalityEvaluations.fingerprint.status)) {
        docData.fingerprintStatus = modalityEvaluations.fingerprint.status;
      }
      const fpDet = modalityEvaluations.fingerprint.details || {};
      if (typeof fpDet.matchedMinutiae === 'number' && Number.isFinite(fpDet.matchedMinutiae)) {
        docData.matchedMinutiae = Math.max(0, Math.min(500, Math.round(fpDet.matchedMinutiae)));
      }
      if (typeof fpDet.probeMinutiae === 'number' && Number.isFinite(fpDet.probeMinutiae)) {
        docData.probeMinutiae = Math.max(0, Math.min(500, Math.round(fpDet.probeMinutiae)));
      }
    }

    debugSummary = {
      identityRef: cleanIdentityRef,
      modalities: safeModalities,
      pipeline: cleanPipeline,
      outcome: safeOutcome,
      finalDecision: docData.finalDecision,
      livenessStatus: docData.livenessStatus,
      reasonCode: cleanReasonCode,
      datasetCategory: derivedDatasetCategory,
      fieldKeys: Object.keys(docData),
    };
    await setDoc(doc(db, 'users', uid, 'verification_records', verificationId), docData);
    trackFsOp('write', t0, true);
    return verificationId;
  } catch (err) {
    trackFsOp('write', t0, false);
    if (err?.operationStage) throw err;
    console.error('Verification record write failed; safe payload summary:', debugSummary);
    handleFirestoreError(err, OperationType.CREATE, path, 'verification_record_creation');
  }
}

export function subscribeVerificationRecords(_role, uid, onData) {
  const path = `users/${uid}/verification_records`;
  const q = query(collection(db, 'users', uid, 'verification_records'), orderBy('createdAt', 'desc'), limit(200));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path, 'verification_record_read')
  );
}

// Append-only Audit Logs (isolated per Google UID)
export async function appendAuditLog({ action, resourceType, resourceId, result, requestId }) {
  const uid = auth.currentUser?.uid;
  if (!uid) return null;
  const eventId = makeId('aud');
  const path = `users/${uid}/audit_logs/${eventId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'audit_logs', eventId), {
      eventId,
      actorUid: uid,
      action: String(action || 'event').trim().slice(0, 80) || 'event',
      resourceType: String(resourceType || 'system').trim().slice(0, 64) || 'system',
      resourceId: String(resourceId || uid).trim().slice(0, 128) || uid,
      result: String(result || 'recorded').trim().slice(0, 240) || 'recorded',
      requestId: String(requestId || makeId('req')).trim().slice(0, 128) || makeId('req'),
      timestamp: serverTimestamp(),
    });
    return eventId;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path, 'audit_logging');
  }
}

export function subscribeAuditLogs(_role, uid, onData) {
  const path = `users/${uid}/audit_logs`;
  const q = query(collection(db, 'users', uid, 'audit_logs'), orderBy('timestamp', 'desc'), limit(200));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path)
  );
}

// Notifications (isolated per Google UID)
export async function pushNotification({ title, message, type = 'info' }) {
  const uid = auth.currentUser?.uid;
  if (!uid) return null;
  const notificationId = makeId('ntf');
  const path = `users/${uid}/notifications/${notificationId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'notifications', notificationId), {
      notificationId,
      userUid: uid,
      title: String(title).slice(0, 140),
      message: String(message).slice(0, 500),
      type,
      read: false,
      createdAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function markNotificationRead(notificationId) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/notifications/${notificationId}`;
  try {
    await updateDoc(doc(db, 'users', uid, 'notifications', notificationId), { read: true });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export function subscribeNotifications(uid, onData) {
  const path = `users/${uid}/notifications`;
  const q = query(collection(db, 'users', uid, 'notifications'), orderBy('createdAt', 'desc'), limit(60));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path)
  );
}

// Security Alerts (Threat Intelligence, isolated per Google UID)
export async function createSecurityAlert({ severity, category, description, assignedTo = '' }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const alertId = makeId('alr');
  const path = `users/${uid}/security_alerts/${alertId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'security_alerts', alertId), {
      alertId,
      severity,
      category: String(category).slice(0, 80),
      description: String(description).slice(0, 600),
      status: 'open',
      assignedTo: String(assignedTo || uid).slice(0, 128),
      notes: '',
      createdBy: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return alertId;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function updateSecurityAlert(alertId, updates) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/security_alerts/${alertId}`;
  try {
    await updateDoc(doc(db, 'users', uid, 'security_alerts', alertId), {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export function subscribeSecurityAlerts(uid, onData) {
  const path = `users/${uid}/security_alerts`;
  const q = query(collection(db, 'users', uid, 'security_alerts'), orderBy('updatedAt', 'desc'), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path)
  );
}

// Automation Workflows (isolated per Google UID)
export async function createWorkflowDoc({ workflowId, name, description, trigger, actions }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const id = (workflowId || makeId('wf')).replace(/[^a-zA-Z0-9_-]/g, '');
  const path = `users/${uid}/automation_workflows/${id}`;
  try {
    await setDoc(doc(db, 'users', uid, 'automation_workflows', id), {
      workflowId: id,
      name: String(name).slice(0, 120),
      description: String(description || '').slice(0, 400),
      enabled: true,
      trigger: String(trigger).slice(0, 80),
      actions: actions.slice(0, 10),
      createdBy: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return id;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function updateWorkflowDoc(workflowId, updates) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/automation_workflows/${workflowId}`;
  try {
    await updateDoc(doc(db, 'users', uid, 'automation_workflows', workflowId), {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export function subscribeWorkflows(uid, onData) {
  const path = `users/${uid}/automation_workflows`;
  const q = query(collection(db, 'users', uid, 'automation_workflows'), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path)
  );
}

// System Settings (isolated per Google UID)
export async function loadSystemSettings() {
  const uid = auth.currentUser?.uid;
  if (!uid) return null;
  const path = `users/${uid}/system_settings/default`;
  try {
    const snap = await getDoc(doc(db, 'users', uid, 'system_settings', 'default'));
    return snap.exists() ? snap.data() : null;
  } catch (err) {
    handleFirestoreError(err, OperationType.GET, path);
  }
}

export async function saveSystemSettings(cfg) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/system_settings/default`;
  const t0 = performance.now();
  try {
    const clampWeight = (val, def) => {
      const n = Number(val);
      return Number.isFinite(n) ? Number(Math.min(1.0, Math.max(0.05, n)).toFixed(3)) : def;
    };
    const payload = {
      settingId: 'default',
      organizationName: String(cfg.organizationName || 'BioGuard X Research').slice(0, 120),
      faceThreshold: Number(cfg.faceThreshold ?? 0.72),
      voiceThreshold: Number(cfg.voiceThreshold ?? 0.70),
      fingerprintThreshold: Number(cfg.fingerprintThreshold ?? 0.72),
      threeModalThreshold: Number(cfg.threeModalThreshold ?? 0.74),
      maxHoldHours: Math.min(4, Math.max(1, Number(cfg.maxHoldHours ?? 4))),
      strictLiveness: cfg.strictLiveness !== false,
      modalityWeights: {
        face: clampWeight(cfg.modalityWeights?.face, 0.45),
        voice: clampWeight(cfg.modalityWeights?.voice, 0.28),
        fingerprint: clampWeight(cfg.modalityWeights?.fingerprint, 0.27),
      },
      updatedAt: serverTimestamp(),
      updatedBy: uid,
    };
    if (['weighted_score', 'strict_and', 'hierarchical_adaptive'].includes(cfg.fusionPolicy)) {
      payload.fusionPolicy = cfg.fusionPolicy;
    }
    if (['balanced', 'strict', 'convenience', 'custom'].includes(cfg.securityPreset)) {
      payload.securityPreset = cfg.securityPreset;
    }
    await setDoc(doc(db, 'users', uid, 'system_settings', 'default'), payload);
    trackFsOp('write', t0, true);
  } catch (err) {
    trackFsOp('write', t0, false);
    handleFirestoreError(err, OperationType.WRITE, path);
  }
}

// Approval Workflow Requests (isolated per Google UID)
export async function createApprovalRequest({ requestType = 'biometric_deletion', targetIdentityRef, reason }) {
  const user = auth.currentUser;
  if (!user) throw new Error('Not signed in');
  const uid = user.uid;
  const requestId = makeId('apr');
  const path = `users/${uid}/approval_requests/${requestId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'approval_requests', requestId), {
      requestId,
      requestType,
      targetIdentityRef: String(targetIdentityRef).slice(0, 64),
      reason: String(reason).slice(0, 500),
      requestedBy: uid,
      requestedByEmail: String(user.email || 'unknown@user').slice(0, 180),
      status: 'pending',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return requestId;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function reviewApprovalRequest(requestId, { status, reviewNotes = '' }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/approval_requests/${requestId}`;
  try {
    await updateDoc(doc(db, 'users', uid, 'approval_requests', requestId), {
      status,
      reviewedBy: uid,
      reviewNotes: String(reviewNotes).slice(0, 500),
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export function subscribeApprovalRequests(_role, uid, onData) {
  const path = `users/${uid}/approval_requests`;
  const q = query(collection(db, 'users', uid, 'approval_requests'), orderBy('updatedAt', 'desc'), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path)
  );
}
