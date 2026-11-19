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
import {
  VALID_FIRESTORE_ID_RE,
  buildVerificationRecordPayload,
  validateVerificationRecordDoc,
} from '../shared/verificationRecord.ts';
import {
  BOOTSTRAPPED_ADMIN_EMAIL,
  classifyFirestoreDiagnostic,
  formatFirebaseAuthDiagnostic,
  isBootstrapAdminEmail,
  sanitizeDiagnosticPayload,
  validateClientFirebaseConfig,
} from '../shared/firestoreDiagnostics.ts';

const clientConfigCheck = validateClientFirebaseConfig(firebaseConfig);
const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

export function getFirebaseTargetInfo() {
  return {
    projectId: clientConfigCheck.projectId,
    databaseId: clientConfigCheck.databaseId,
    configValid: clientConfigCheck.valid,
  };
}

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

function makeDiagnosticError(message, operationStage, code, extra = {}) {
  const err = new Error(message);
  const classified = classifyFirestoreDiagnostic({
    code: code || operationStage,
    operationStage,
    message,
    projectId: clientConfigCheck.projectId,
    databaseId: clientConfigCheck.databaseId,
    configValid: clientConfigCheck.valid,
    isAuthenticated: Boolean(auth.currentUser?.uid),
    emailVerified: auth.currentUser?.emailVerified,
    isBootstrapAdmin: isBootstrapAdminEmail(auth.currentUser?.email, auth.currentUser?.emailVerified),
    ...extra,
  });
  return Object.assign(err, {
    operationStage,
    code: code || operationStage,
    httpStatus: classified.httpStatus,
    status: classified.httpStatus,
    projectId: classified.projectId,
    databaseId: classified.databaseId,
    diagnosticCode: classified.diagnosticCode,
    diagnosticCategory: classified.diagnosticCategory,
    diagnosticTitle: classified.diagnosticTitle,
    diagnosticExplanation: classified.diagnosticExplanation,
    diagnosticRemediation: classified.diagnosticRemediation,
    ...extra,
  });
}

async function probeUserWorkspaceState(uid) {
  if (!uid || !clientConfigCheck.valid) return { probed: false };
  const ref = doc(db, 'users', uid);
  try {
    let snap;
    try {
      snap = await getDocFromServer(ref);
    } catch {
      snap = await getDoc(ref);
    }
    if (!snap.exists()) {
      return {
        probed: true,
        userDocExists: false,
        userRole: null,
        userStatus: null,
      };
    }
    const data = snap.data() || {};
    return {
      probed: true,
      userDocExists: true,
      userRole: typeof data.role === 'string' ? data.role : null,
      userStatus: typeof data.status === 'string' ? data.status : null,
    };
  } catch (probeErr) {
    return {
      probed: false,
      probeErrorCode: String(probeErr?.code || 'unknown'),
    };
  }
}

export function handleFirestoreError(
  error,
  operationType,
  path,
  operationStage = null,
  payloadSummary = null,
  diagnosticContext = null
) {
  const user = auth.currentUser;
  const errInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: user?.uid || null,
      email: user?.email || null,
      emailVerified: user?.emailVerified ?? null,
      isAnonymous: user?.isAnonymous ?? null,
      tenantId: user?.tenantId || null,
      providerInfo:
        user?.providerData?.map((p) => ({
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
  const classified = classifyFirestoreDiagnostic({
    code: rawCode ? `firestore_${rawCode.replace(/[^a-zA-Z0-9_]/g, '_')}` : 'firestore_error',
    rawCode,
    operationStage: operationStage || error?.operationStage || operationType,
    operationType,
    path,
    message: errInfo.error,
    projectId: clientConfigCheck.projectId,
    databaseId: clientConfigCheck.databaseId,
    configValid: clientConfigCheck.valid,
    isAuthenticated: Boolean(user?.uid),
    emailVerified: user?.emailVerified,
    isBootstrapAdmin: isBootstrapAdminEmail(user?.email, user?.emailVerified),
    ...(diagnosticContext || {}),
  });
  const safePayloadSummary = payloadSummary ? sanitizeDiagnosticPayload(payloadSummary) : null;
  const workspaceDiagnostics = diagnosticContext
    ? sanitizeDiagnosticPayload({
        userDocExists: diagnosticContext.userDocExists ?? null,
        userRole: diagnosticContext.userRole ?? null,
        userStatus: diagnosticContext.userStatus ?? null,
        identityExists: diagnosticContext.identityExists ?? null,
        identityStatus: diagnosticContext.identityStatus ?? null,
        emailVerified: user?.emailVerified ?? null,
        isBootstrapAdmin: isBootstrapAdminEmail(user?.email, user?.emailVerified),
      })
    : null;
  const httpStatus = classified.httpStatus || (rawCode === 'permission-denied' ? 403 : rawCode === 'unauthenticated' ? 401 : undefined);
  const wrapped = Object.assign(new Error(serialized, { cause: error }), {
    code: rawCode ? `firestore_${rawCode.replace(/[^a-zA-Z0-9_]/g, '_')}` : 'firestore_error',
    upstreamCode: rawCode || undefined,
    ...(httpStatus ? { status: httpStatus, httpStatus } : {}),
    operationStage: operationStage || error?.operationStage || operationType,
    operationType,
    path,
    projectId: classified.projectId,
    databaseId: classified.databaseId,
    diagnosticCode: classified.diagnosticCode,
    diagnosticCategory: classified.diagnosticCategory,
    diagnosticTitle: classified.diagnosticTitle,
    diagnosticExplanation: classified.diagnosticExplanation,
    diagnosticRemediation: classified.diagnosticRemediation,
    ...(workspaceDiagnostics ? { workspaceDiagnostics } : {}),
    ...(safePayloadSummary ? { payloadSummary: safePayloadSummary } : {}),
    isFirestoreError: true,
  });
  throw wrapped;
}

// Connection check on boot
export async function testFirestoreConnection() {
  if (!clientConfigCheck.valid) {
    return {
      connected: false,
      code: 'wrong_firestore_database',
      projectId: clientConfigCheck.projectId,
      databaseId: clientConfigCheck.databaseId,
      error: clientConfigCheck.reason,
    };
  }
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
    return { connected: true, projectId: clientConfigCheck.projectId, databaseId: clientConfigCheck.databaseId };
  } catch (error) {
    const rawCode = String(error?.code || '');
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('the client is offline') || rawCode === 'unavailable' || rawCode === 'deadline-exceeded') {
      return {
        connected: false,
        code: 'network_failure',
        projectId: clientConfigCheck.projectId,
        databaseId: clientConfigCheck.databaseId,
        error: 'Firestore client is offline or unreachable. Check network connection and Firebase configuration.',
      };
    }
    if (/database .* does not exist|database .* not found/i.test(msg)) {
      return {
        connected: false,
        code: 'wrong_firestore_database',
        projectId: clientConfigCheck.projectId,
        databaseId: clientConfigCheck.databaseId,
        error: msg,
      };
    }
    // Permission denied on /test/connection still proves server reachability
    return { connected: true, projectId: clientConfigCheck.projectId, databaseId: clientConfigCheck.databaseId };
  }
}

export function formatFirebaseAuthError(err) {
  const hostname = typeof window !== 'undefined' ? window.location?.hostname || '' : '';
  const diag = formatFirebaseAuthDiagnostic(err, hostname, firebaseConfig.authDomain);
  const out = new Error(diag.formattedMessage, { cause: err });
  return Object.assign(out, {
    code: diag.code,
    authDiagnostic: diag,
  });
}

export function isEmbeddedPreview() {
  try {
    return typeof window !== 'undefined' && window.self !== window.top;
  } catch {
    return true;
  }
}

let prewarmPromise = null;

export function prewarmGoogleAuthPopup() {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return Promise.resolve(false);
  }
  if (prewarmPromise) return prewarmPromise;

  prewarmPromise = (async () => {
    try {
      if (auth._initializationPromise) {
        await auth._initializationPromise;
      }
      const resolver = auth._popupRedirectResolver;
      if (resolver && typeof resolver._initialize === 'function') {
        await resolver._initialize(auth);
      }
      if (resolver && typeof resolver._originValidation === 'function') {
        resolver._originValidation(auth).catch(() => null);
      }
      return true;
    } catch {
      prewarmPromise = null;
      return false;
    }
  })();

  return prewarmPromise;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  void prewarmGoogleAuthPopup();
}

export async function resolveAuthRedirect() {
  try {
    const result = await getRedirectResult(auth);
    return result?.user || null;
  } catch (err) {
    console.warn('Google redirect sign-in returned error:', err?.message || err);
    throw formatFirebaseAuthError(err);
  }
}

export async function signInWithGoogle() {
  const isStandalone =
    typeof window !== 'undefined' &&
    (window.matchMedia?.('(display-mode: standalone)')?.matches === true || window.navigator?.standalone === true);
  const inIframe = isEmbeddedPreview();

  if (isStandalone && !inIframe) {
    try {
      await signInWithRedirect(auth, googleProvider);
      return null;
    } catch (err) {
      throw formatFirebaseAuthError(err);
    }
  }
  try {
    const cred = await signInWithPopup(auth, googleProvider);
    return cred.user;
  } catch (err) {
    const code = err?.code || '';
    const isIframeRestrictedCode =
      code === 'auth/popup-blocked' ||
      code === 'auth/operation-not-supported-in-this-environment' ||
      code === 'auth/cancelled-popup-request' ||
      code === 'auth/web-storage-unsupported' ||
      code === 'auth/internal-error' ||
      code === 'auth/network-request-failed';

    if (inIframe && (isIframeRestrictedCode || code === 'auth/popup-closed-by-user')) {
      const hostname = typeof window !== 'undefined' ? window.location?.hostname || '' : '';
      const isClosed = code === 'auth/popup-closed-by-user';
      const title = isClosed ? 'Sign-In Popup Closed Inside Preview' : 'Preview Iframe Blocked Sign-In Popup';
      const msg = isClosed
        ? `The Google Sign-In popup closed before completing inside the embedded preview (${hostname}). Click "Open App in New Tab" below if your browser prevented the preview popup from staying open.`
        : `Sign-In popup could not complete inside the embedded preview (${hostname}, code: ${code}). Click "Open App in New Tab" below or allow popups & third-party cookies for this preview host.`;
      const iframeErr = new Error(msg, { cause: err });
      throw Object.assign(iframeErr, {
        code: isClosed ? 'auth/popup-closed-by-user' : 'auth/popup-blocked',
        authDiagnostic: {
          code: isClosed ? 'auth/popup-closed-by-user' : 'auth/popup-blocked',
          title,
          explanation: 'Embedded preview iframes frequently restrict Google OAuth popups or third-party storage.',
          remediation: 'Click "Open App in New Tab" below or allow popups for this site, then sign in with Google.',
          hostname,
          authDomain: firebaseConfig.authDomain,
          formattedMessage: iframeErr.message,
        },
      });
    }

    if (
      !inIframe &&
      (code === 'auth/popup-blocked' ||
        code === 'auth/operation-not-supported-in-this-environment' ||
        code === 'auth/cancelled-popup-request')
    ) {
      try {
        await signInWithRedirect(auth, googleProvider);
        return null;
      } catch (redirErr) {
        throw formatFirebaseAuthError(redirErr);
      }
    }
    throw formatFirebaseAuthError(err);
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

export function makeVerificationRecordId() {
  return makeId('ver');
}

const VALID_IDENTITY_RE = /^[a-zA-Z0-9_-]{2,64}$/;
const SUPPORTED_MODALITIES = new Set(['face', 'voice', 'fingerprint']);

// Idempotent user provisioning & bootstrap admin self-healing in /users/{uid} and /admins/{uid}
export async function provisionUserProfile(fbUser) {
  if (!clientConfigCheck.valid) {
    throw makeDiagnosticError(
      clientConfigCheck.reason,
      'user_profile_provisioning',
      'wrong_firestore_database'
    );
  }
  if (!fbUser?.uid) {
    throw makeDiagnosticError('Authenticated user UID is missing.', 'user_profile_provisioning', 'unauthenticated');
  }
  if (!fbUser.emailVerified) {
    throw makeDiagnosticError(
      'Verified Google email address is required before provisioning profile.',
      'user_profile_provisioning',
      'email_not_verified',
      { emailVerified: false }
    );
  }

  const userPath = `users/${fbUser.uid}`;
  const ref = doc(db, 'users', fbUser.uid);
  const adminRef = doc(db, 'admins', fbUser.uid);
  const isBootstrap =
    fbUser.emailVerified === true &&
    String(fbUser.email || '').trim().toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL;

  let existingState = null;
  try {
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      existingState = { userDocExists: false, userRole: isBootstrap ? 'super_admin' : 'operator', userStatus: 'active' };
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
      const existingData = snap.data() || {};
      existingState = {
        userDocExists: true,
        userRole: typeof existingData.role === 'string' ? existingData.role : null,
        userStatus: typeof existingData.status === 'string' ? existingData.status : null,
      };
      if (!isBootstrap && existingData.status === 'suspended') {
        throw makeDiagnosticError(
          'Your BioGuard X operator account is suspended.',
          'account_status',
          'account_suspended',
          { ...existingState, path: userPath }
        );
      }
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
    if (err?.diagnosticCode || err?.operationStage) throw err;
    handleFirestoreError(err, OperationType.WRITE, userPath, 'user_profile_provisioning', null, {
      ...(existingState || {}),
      isBootstrapAdmin: isBootstrap,
    });
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
  const t0 = performance.now();
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
        status: 'active',
        registeredModalities: cleanModalities,
        featureVersion: String(featureVersion || 'v2.0-multimodal').slice(0, 32),
        updatedAt: serverTimestamp(),
      });
    }

    // Confirm persistence by reading the saved metadata document back from Firestore
    let confirmedSnap;
    try {
      confirmedSnap = await getDocFromServer(ref);
    } catch {
      confirmedSnap = await getDoc(ref);
    }
    if (!confirmedSnap.exists() || confirmedSnap.data()?.identityRef !== cleanRef) {
      throw makeDiagnosticError(
        `Identity metadata write for "${cleanRef}" could not be confirmed on Firestore read-back.`,
        'identity_enrollment',
        'identity_metadata_readback_failed',
        { path }
      );
    }
    trackFsOp('write', t0, true);
    return confirmedSnap.data();
  } catch (err) {
    trackFsOp('write', t0, false);
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
  const docRef = doc(db, 'users', uid, 'identities', identityRef);
  try {
    await deleteDoc(docRef);
    let checkSnap = null;
    try {
      checkSnap = await getDocFromServer(docRef);
    } catch {
      checkSnap = await getDoc(docRef).catch(() => null);
    }
    if (checkSnap && checkSnap.exists()) {
      throw makeDiagnosticError(
        `Identity metadata "${identityRef}" still exists after deletion request.`,
        'identity_deletion',
        'identity_delete_verification_failed',
        { path }
      );
    }
  } catch (err) {
    if (err?.operationStage) throw err;
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
  verificationId: requestedVerificationId,
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
  if (!clientConfigCheck.valid) {
    throw makeDiagnosticError(
      clientConfigCheck.reason,
      'verification_record_validation',
      'wrong_firestore_database'
    );
  }

  const user = auth.currentUser;
  const uid = user?.uid;
  if (!uid) throw makeDiagnosticError('Not signed in.', 'verification_record_validation', 'unauthenticated');
  if (user.emailVerified !== true) {
    throw makeDiagnosticError(
      'Verified Google email address is required before creating verification records.',
      'email_verification',
      'email_not_verified',
      { emailVerified: false }
    );
  }

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
  let identityProbe = {
    identityExists: null,
    identityStatus: null,
    identityRefMatches: null,
  };
  try {
    const idSnap = await getDoc(doc(db, 'users', uid, 'identities', cleanIdentityRef));
    if (!idSnap.exists()) {
      throw makeDiagnosticError(
        `Identity metadata not found at "${identityPath}". Re-enroll identity metadata before verifying.`,
        'identity_lookup',
        'identity_metadata_missing',
        { path: identityPath, identityExists: false }
      );
    }
    const idData = idSnap.data();
    if (idData.status !== 'active') {
      throw makeDiagnosticError(
        `Identity "${cleanIdentityRef}" is currently "${idData.status}" and cannot accept new verification records.`,
        'identity_lookup',
        'identity_inactive',
        { path: identityPath, identityExists: true, identityStatus: idData.status, identityRefMatches: idData.identityRef === cleanIdentityRef }
      );
    }
    if (idData.identityRef !== cleanIdentityRef) {
      throw makeDiagnosticError(
        `Identity metadata integrity mismatch at "${identityPath}" (document identityRef="${idData.identityRef}").`,
        'identity_lookup',
        'identity_ref_mismatch',
        { path: identityPath, identityExists: true, identityStatus: idData.status, identityRefMatches: false }
      );
    }
    identityProbe = {
      identityExists: true,
      identityStatus: idData.status,
      identityRefMatches: true,
    };
  } catch (err) {
    if (err?.diagnosticCode || err?.operationStage) throw err;
    const userState = await probeUserWorkspaceState(uid);
    handleFirestoreError(err, OperationType.GET, identityPath, 'identity_lookup', null, {
      ...userState,
    });
  }

  let verificationId = makeVerificationRecordId();
  if (requestedVerificationId !== undefined && requestedVerificationId !== null) {
    const cleanVerId = String(requestedVerificationId).trim();
    if (!VALID_FIRESTORE_ID_RE.test(cleanVerId)) {
      throw makeDiagnosticError(
        'Verification record rejected: invalid verificationId format.',
        'verification_record_validation',
        'verification_record_schema_invalid'
      );
    }
    verificationId = cleanVerId;
  }
  const path = `users/${uid}/verification_records/${verificationId}`;
  const t0 = performance.now();
  let debugSummary = null;
  try {
    const docData = buildVerificationRecordPayload({
      uid,
      verificationId,
      identityRef: cleanIdentityRef,
      modalities: safeModalities,
      pipeline,
      outcome,
      finalDecision,
      livenessStatus,
      livenessDecision,
      challengeVerified,
      datasetCategory,
      captureFailure,
      reasonCode,
      score,
      confidence,
      identityConfidence,
      sampleQualityScore,
      livenessConfidence,
      confidenceBand,
      conflictDetected,
      processingTimeMs,
      featureVersion,
      groundTruth,
      isTestProbe,
      modalityEvaluations,
      riskScore,
      riskLevel,
      livenessPassed,
      livenessScore,
      adaptiveApplied,
      subjectKey,
      partition,
      sampleHash,
      benchmarkBatchId,
      provenanceSignature,
      createdAt: serverTimestamp(),
    });

    const schemaCheck = validateVerificationRecordDoc(docData, uid, verificationId);
    if (!schemaCheck.valid) {
      throw makeDiagnosticError(
        `Verification record payload failed pre-write validation: ${schemaCheck.errors.join(' ')}`,
        'verification_record_validation',
        'verification_record_schema_invalid',
        { schemaValid: false, schemaErrors: schemaCheck.errors }
      );
    }

    debugSummary = sanitizeDiagnosticPayload({
      identityRef: cleanIdentityRef,
      modalities: safeModalities,
      pipeline: docData.pipeline,
      outcome: docData.outcome,
      finalDecision: docData.finalDecision,
      livenessStatus: docData.livenessStatus,
      reasonCode: docData.reasonCode,
      datasetCategory: docData.datasetCategory,
      fieldCount: Object.keys(docData).length,
      fieldKeys: Object.keys(docData),
    });
    await setDoc(doc(db, 'users', uid, 'verification_records', verificationId), docData);
    trackFsOp('write', t0, true);
    return verificationId;
  } catch (err) {
    trackFsOp('write', t0, false);
    if (err?.diagnosticCode || err?.operationStage) throw err;
    const userState = await probeUserWorkspaceState(uid);
    console.error('Verification record write failed; safe payload summary:', debugSummary);
    handleFirestoreError(err, OperationType.CREATE, path, 'verification_record_creation', debugSummary, {
      ...userState,
      ...identityProbe,
      schemaValid: true,
    });
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
