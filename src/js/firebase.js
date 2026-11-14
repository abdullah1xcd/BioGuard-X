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

export function handleFirestoreError(error, operationType, path) {
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
  console.error('Firestore Error:', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
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

// Provision or refresh user profile in /users/{uid}
export async function provisionUserProfile(fbUser) {
  const userPath = `users/${fbUser.uid}`;
  const ref = doc(db, 'users', fbUser.uid);
  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      const isBootstrap = fbUser.emailVerified && fbUser.email === BOOTSTRAPPED_ADMIN_EMAIL;
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
        await setDoc(doc(db, 'admins', fbUser.uid), {
          uid: fbUser.uid,
          role: 'super_admin',
          grantedBy: fbUser.uid,
          createdAt: serverTimestamp(),
        });
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
      await updateDoc(ref, updates);
      const updated = await getDoc(ref);
      return updated.data();
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, userPath);
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
  if (!uid) throw new Error('Not signed in');
  const path = `users/${uid}/identities/${identityRef}`;
  try {
    const ref = doc(db, 'users', uid, 'identities', identityRef);
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, {
        identityId: identityRef,
        identityRef,
        displayName: displayName.slice(0, 120),
        status: 'active',
        registeredModalities: registeredModalities.slice(0, 3),
        featureVersion: featureVersion || 'v1.0-classical',
        consentRecorded: true,
        createdBy: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        displayName: displayName.slice(0, 120),
        registeredModalities: registeredModalities.slice(0, 3),
        featureVersion: featureVersion || 'v1.0-classical',
        updatedAt: serverTimestamp(),
      });
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, path);
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
    (snap) => onData(snap.docs.map((d) => d.data())),
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
  if (!uid) throw new Error('Not signed in');
  const verificationId = makeId('ver');
  const path = `users/${uid}/verification_records/${verificationId}`;
  const t0 = performance.now();
  try {
    // Build a Firestore-rules-safe record. Matcher telemetry can contain NaN/Infinity
    // when a modality is unavailable; those values must never be sent to Firestore.
    const safeModalities = Array.isArray(modalities)
      ? modalities.filter((item) => typeof item === 'string' && item.length > 0).slice(0, 3)
      : [];
    if (!identityRef || typeof identityRef !== 'string' || identityRef.length > 64) {
      throw new Error('Verification record rejected: invalid identity reference.');
    }
    if (safeModalities.length === 0) {
      throw new Error('Verification record rejected: no valid modalities were evaluated.');
    }
    const safeOutcome = ['match', 'no_match', 'not_evaluated'].includes(outcome) ? outcome : 'not_evaluated';
    const safeGroundTruth = ['genuine', 'impostor', 'unlabeled'].includes(groundTruth) ? groundTruth : 'unlabeled';
    const derivedDatasetCategory = ['operational', 'synthetic_qa', 'benchmark_eval'].includes(datasetCategory)
      ? datasetCategory
      : (isTestProbe ? 'synthetic_qa' : safeGroundTruth !== 'unlabeled' ? 'benchmark_eval' : 'operational');
    const finiteClamp = (value, min, max, digits = 3) =>
      typeof value === 'number' && Number.isFinite(value)
        ? Number(Math.min(max, Math.max(min, value)).toFixed(digits))
        : null;
    const safeScore = finiteClamp(score, 0, 1, 4);
    const docData = {
      verificationId,
      identityRef,
      modalities: safeModalities,
      pipeline: String(pipeline || 'hierarchical').slice(0, 64),
      outcome: safeOutcome,
      policyDecision: 'pending',
      reasonCode: String(reasonCode || 'evaluated').slice(0, 80),
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
    if (typeof riskScore === 'number') docData.riskScore = Math.min(100, Math.max(0, Math.round(riskScore)));
    if (['low', 'medium', 'high', 'critical'].includes(riskLevel)) docData.riskLevel = riskLevel;
    if (typeof livenessPassed === 'boolean') docData.livenessPassed = livenessPassed;
    { const value = finiteClamp(livenessScore, 0, 1, 2); if (value !== null) docData.livenessScore = value; }
    if (typeof adaptiveApplied === 'boolean') docData.adaptiveApplied = adaptiveApplied;
    if (['genuine', 'impostor', 'unlabeled'].includes(groundTruth)) docData.groundTruth = groundTruth;
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
    if (typeof featureVersion === 'string' && featureVersion.length > 0) {
      docData.featureVersion = featureVersion.slice(0, 32);
    }
    if (typeof subjectKey === 'string' && subjectKey.length > 0) {
      docData.subjectKey = subjectKey.slice(0, 80);
    }
    if (partition === 'eval' || partition === 'unassigned') {
      docData.partition = partition;
    }
    if (typeof sampleHash === 'string' && sampleHash.length > 0) {
      docData.sampleHash = sampleHash.slice(0, 128);
    }
    if (typeof benchmarkBatchId === 'string' && benchmarkBatchId.length > 0) {
      docData.benchmarkBatchId = benchmarkBatchId.slice(0, 80);
    }
    if (typeof provenanceSignature === 'string' && provenanceSignature.length > 0) {
      docData.provenanceSignature = provenanceSignature.slice(0, 160);
    }

    if (modalityEvaluations?.face) {
      { const value = finiteClamp(modalityEvaluations.face.score, 0, 1, 4); if (value !== null) docData.faceScore = value; }
      { const value = finiteClamp(modalityEvaluations.face.qualityScore, 0, 100, 0); if (value !== null) docData.faceQuality = value; }
      if (['MATCH', 'NO MATCH', 'INCONCLUSIVE'].includes(modalityEvaluations.face.status)) {
        docData.faceStatus = modalityEvaluations.face.status;
      }
    }
    if (modalityEvaluations?.voice) {
      { const value = finiteClamp(modalityEvaluations.voice.score, 0, 1, 4); if (value !== null) docData.voiceScore = value; }
      { const value = finiteClamp(modalityEvaluations.voice.qualityScore, 0, 100, 0); if (value !== null) docData.voiceQuality = value; }
      if (['MATCH', 'NO MATCH', 'INCONCLUSIVE'].includes(modalityEvaluations.voice.status)) {
        docData.voiceStatus = modalityEvaluations.voice.status;
      }
    }
    if (modalityEvaluations?.fingerprint) {
      { const value = finiteClamp(modalityEvaluations.fingerprint.score, 0, 1, 4); if (value !== null) docData.fingerprintScore = value; }
      { const value = finiteClamp(modalityEvaluations.fingerprint.qualityScore, 0, 100, 0); if (value !== null) docData.fingerprintQuality = value; }
      if (['MATCH', 'NO MATCH', 'INCONCLUSIVE'].includes(modalityEvaluations.fingerprint.status)) {
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

    await setDoc(doc(db, 'users', uid, 'verification_records', verificationId), docData);
    trackFsOp('write', t0, true);
    return verificationId;
  } catch (err) {
    trackFsOp('write', t0, false);
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export function subscribeVerificationRecords(_role, uid, onData) {
  const path = `users/${uid}/verification_records`;
  const q = query(collection(db, 'users', uid, 'verification_records'), orderBy('createdAt', 'desc'), limit(200));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, path)
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
      action: String(action).slice(0, 80),
      resourceType: String(resourceType).slice(0, 64),
      resourceId: String(resourceId).slice(0, 128),
      result: String(result).slice(0, 240),
      requestId: String(requestId || makeId('req')).slice(0, 128),
      timestamp: serverTimestamp(),
    });
    return eventId;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
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
