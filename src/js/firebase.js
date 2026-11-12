import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
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
  where,
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

export async function signInWithGoogle() {
  const cred = await signInWithPopup(auth, googleProvider);
  return cred.user;
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
      const initialRole = isBootstrap ? 'super_admin' : 'viewer';
      const payload = {
        uid: fbUser.uid,
        displayName: (fbUser.displayName || fbUser.email || 'Operator').slice(0, 120),
        email: (fbUser.email || '').slice(0, 180),
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
      await updateDoc(ref, {
        displayName: (fbUser.displayName || snap.data().displayName || 'Operator').slice(0, 120),
        photoURL: (fbUser.photoURL || snap.data().photoURL || '').slice(0, 500),
        lastLoginAt: serverTimestamp(),
      });
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

// Identities Metadata (NO vectors stored here)
export async function saveIdentityMetadata({ identityRef, displayName, registeredModalities, featureVersion }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const path = `identities/${identityRef}`;
  try {
    const ref = doc(db, 'identities', identityRef);
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
  const path = `identities/${identityRef}`;
  try {
    await updateDoc(doc(db, 'identities', identityRef), {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function deleteIdentityMetadata(identityRef) {
  const path = `identities/${identityRef}`;
  try {
    await deleteDoc(doc(db, 'identities', identityRef));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

export function subscribeIdentities(role, uid, onData, onErr) {
  const isOp = ['super_admin', 'administrator', 'security_analyst', 'operator'].includes(role);
  const q = isOp
    ? query(collection(db, 'identities'), orderBy('updatedAt', 'desc'), limit(150))
    : query(collection(db, 'identities'), where('createdBy', '==', uid), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => {
      if (onErr) onErr(err);
      else handleFirestoreError(err, OperationType.LIST, 'identities');
    }
  );
}

// Verification Records
export async function recordVerificationMetadata({
  identityRef,
  modalities,
  pipeline,
  outcome,
  reasonCode,
  score,
  riskScore,
  riskLevel,
  livenessPassed,
  livenessScore,
  adaptiveApplied,
}) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const verificationId = makeId('ver');
  const path = `verification_records/${verificationId}`;
  try {
    const docData = {
      verificationId,
      identityRef,
      modalities: modalities.slice(0, 3),
      pipeline: String(pipeline || 'hierarchical').slice(0, 64),
      outcome,
      policyDecision: 'pending',
      reasonCode: String(reasonCode || 'evaluated').slice(0, 80),
      score: typeof score === 'number' ? Number(score.toFixed(4)) : 0,
      operatorUid: uid,
      createdAt: serverTimestamp(),
    };
    if (typeof riskScore === 'number') docData.riskScore = Math.min(100, Math.max(0, Math.round(riskScore)));
    if (['low', 'medium', 'high', 'critical'].includes(riskLevel)) docData.riskLevel = riskLevel;
    if (typeof livenessPassed === 'boolean') docData.livenessPassed = livenessPassed;
    if (typeof livenessScore === 'number') docData.livenessScore = Number(Math.min(1, Math.max(0, livenessScore)).toFixed(2));
    if (typeof adaptiveApplied === 'boolean') docData.adaptiveApplied = adaptiveApplied;

    await setDoc(doc(db, 'verification_records', verificationId), docData);
    return verificationId;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export function subscribeVerificationRecords(role, uid, onData) {
  const isAnalyst = ['super_admin', 'administrator', 'security_analyst'].includes(role);
  const q = isAnalyst
    ? query(collection(db, 'verification_records'), orderBy('createdAt', 'desc'), limit(200))
    : query(collection(db, 'verification_records'), where('operatorUid', '==', uid), limit(150));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, 'verification_records')
  );
}

// Append-only Audit Logs
export async function appendAuditLog({ action, resourceType, resourceId, result, requestId }) {
  const uid = auth.currentUser?.uid;
  if (!uid) return null;
  const eventId = makeId('aud');
  const path = `audit_logs/${eventId}`;
  try {
    await setDoc(doc(db, 'audit_logs', eventId), {
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

export function subscribeAuditLogs(role, uid, onData) {
  const isAnalyst = ['super_admin', 'administrator', 'security_analyst'].includes(role);
  const q = isAnalyst
    ? query(collection(db, 'audit_logs'), orderBy('timestamp', 'desc'), limit(200))
    : query(collection(db, 'audit_logs'), where('actorUid', '==', uid), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, 'audit_logs')
  );
}

// Notifications
export async function pushNotification({ title, message, type = 'info', targetUid = null }) {
  const uid = targetUid || auth.currentUser?.uid;
  if (!uid) return null;
  const notificationId = makeId('ntf');
  const path = `notifications/${notificationId}`;
  try {
    await setDoc(doc(db, 'notifications', notificationId), {
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
  try {
    await updateDoc(doc(db, 'notifications', notificationId), { read: true });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, `notifications/${notificationId}`);
  }
}

export function subscribeNotifications(uid, onData) {
  const q = query(collection(db, 'notifications'), where('userUid', '==', uid), limit(60));
  return onSnapshot(
    q,
    (snap) => {
      const items = snap.docs.map((d) => d.data());
      items.sort((a, b) => (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0));
      onData(items);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'notifications')
  );
}

// Security Alerts (Threat Intelligence)
export async function createSecurityAlert({ severity, category, description, assignedTo = '' }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const alertId = makeId('alr');
  try {
    await setDoc(doc(db, 'security_alerts', alertId), {
      alertId,
      severity,
      category: String(category).slice(0, 80),
      description: String(description).slice(0, 600),
      status: 'open',
      assignedTo: String(assignedTo).slice(0, 128),
      notes: '',
      createdBy: uid,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return alertId;
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, `security_alerts/${alertId}`);
  }
}

export async function updateSecurityAlert(alertId, updates) {
  try {
    await updateDoc(doc(db, 'security_alerts', alertId), {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, `security_alerts/${alertId}`);
  }
}

export function subscribeSecurityAlerts(onData) {
  const q = query(collection(db, 'security_alerts'), orderBy('updatedAt', 'desc'), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, 'security_alerts')
  );
}

// Automation Workflows
export async function createWorkflowDoc({ workflowId, name, description, trigger, actions }) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  const id = (workflowId || makeId('wf')).replace(/[^a-zA-Z0-9_-]/g, '');
  try {
    await setDoc(doc(db, 'automation_workflows', id), {
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
    handleFirestoreError(err, OperationType.CREATE, `automation_workflows/${id}`);
  }
}

export async function updateWorkflowDoc(workflowId, updates) {
  try {
    await updateDoc(doc(db, 'automation_workflows', workflowId), {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, `automation_workflows/${workflowId}`);
  }
}

export function subscribeWorkflows(onData) {
  const q = query(collection(db, 'automation_workflows'), limit(100));
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => d.data())),
    (err) => handleFirestoreError(err, OperationType.LIST, 'automation_workflows')
  );
}

// System Settings
export async function loadSystemSettings() {
  try {
    const snap = await getDoc(doc(db, 'system_settings', 'default'));
    return snap.exists() ? snap.data() : null;
  } catch (err) {
    handleFirestoreError(err, OperationType.GET, 'system_settings/default');
  }
}

export async function saveSystemSettings(cfg) {
  const uid = auth.currentUser?.uid;
  if (!uid) throw new Error('Not signed in');
  try {
    await setDoc(doc(db, 'system_settings', 'default'), {
      settingId: 'default',
      organizationName: String(cfg.organizationName || 'BioGuard X Research').slice(0, 120),
      faceThreshold: Number(cfg.faceThreshold ?? 0.72),
      voiceThreshold: Number(cfg.voiceThreshold ?? 0.70),
      fingerprintThreshold: Number(cfg.fingerprintThreshold ?? 0.72),
      threeModalThreshold: Number(cfg.threeModalThreshold ?? 0.74),
      maxHoldHours: Math.min(4, Math.max(1, Number(cfg.maxHoldHours ?? 4))),
      updatedAt: serverTimestamp(),
      updatedBy: uid,
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, 'system_settings/default');
  }
}

// Approval Workflow Requests
export async function createApprovalRequest({ requestType = 'biometric_deletion', targetIdentityRef, reason }) {
  const user = auth.currentUser;
  if (!user) throw new Error('Not signed in');
  const requestId = makeId('apr');
  const path = `approval_requests/${requestId}`;
  try {
    await setDoc(doc(db, 'approval_requests', requestId), {
      requestId,
      requestType,
      targetIdentityRef: String(targetIdentityRef).slice(0, 64),
      reason: String(reason).slice(0, 500),
      requestedBy: user.uid,
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
  const path = `approval_requests/${requestId}`;
  try {
    await updateDoc(doc(db, 'approval_requests', requestId), {
      status,
      reviewedBy: uid,
      reviewNotes: String(reviewNotes).slice(0, 500),
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export function subscribeApprovalRequests(role, uid, onData) {
  const isAdminRole = ['super_admin', 'administrator'].includes(role);
  const q = isAdminRole
    ? query(collection(db, 'approval_requests'), orderBy('updatedAt', 'desc'), limit(100))
    : query(collection(db, 'approval_requests'), where('requestedBy', '==', uid), limit(60));
  return onSnapshot(
    q,
    (snap) => {
      const items = snap.docs.map((d) => d.data());
      items.sort((a, b) => (b.updatedAt?.toMillis?.() || 0) - (a.updatedAt?.toMillis?.() || 0));
      onData(items);
    },
    (err) => handleFirestoreError(err, OperationType.LIST, 'approval_requests')
  );
}
