import {
  VERIFICATION_RECORD_ALLOWED_KEYS,
  VERIFICATION_RECORD_REQUIRED_KEYS,
  VALID_FIRESTORE_ID_RE,
  VALID_IDENTITY_REF_RE,
  VERIFICATION_SUPPORTED_MODALITIES,
} from './verificationRecord.ts';

export const EXPECTED_FIREBASE_PROJECT_ID = 'basic-climber-rmbw7';
export const EXPECTED_FIRESTORE_DATABASE_ID = 'ai-studio-bioguardx-e1593f08-43df-4912-a9e0-6922af3760d4';
export const BOOTSTRAPPED_ADMIN_EMAIL = 'abdullahmohamedharoon8@gmail.com';

export type DiagnosticCategory =
  | 'unauthenticated'
  | 'backend_auth_failure'
  | 'email_not_verified'
  | 'wrong_firestore_database'
  | 'user_profile_missing'
  | 'account_suspended'
  | 'unauthorized_role'
  | 'identity_metadata_missing'
  | 'identity_inactive'
  | 'verification_record_schema_invalid'
  | 'undeployed_or_outdated_security_rules'
  | 'network_failure'
  | 'firestore_permission_denied'
  | 'vault_secret_not_configured'
  | 'vault_decryption_failed'
  | 'vault_storage_error'
  | 'missing_vault_template'
  | 'feature_version_mismatch'
  | 'biometric_quality_rejected'
  | 'biometric_sample_invalid'
  | 'rate_limited'
  | 'rate_limiter_unavailable'
  | 'cors_origin_denied'
  | 'ai_service_unavailable'
  | 'api_request_error';

export interface ClientFirebaseConfigInput {
  projectId?: unknown;
  firestoreDatabaseId?: unknown;
}

export interface ClientFirebaseConfigCheck {
  valid: boolean;
  projectId: string;
  databaseId: string;
  errorCode?: 'wrong_firestore_database';
  reason?: string;
}

export function validateClientFirebaseConfig(cfg: ClientFirebaseConfigInput | null | undefined): ClientFirebaseConfigCheck {
  const projectId = typeof cfg?.projectId === 'string' ? cfg.projectId.trim() : '';
  const databaseId = typeof cfg?.firestoreDatabaseId === 'string' ? cfg.firestoreDatabaseId.trim() : '';

  if (!projectId || !/^[a-z0-9-]+$/.test(projectId)) {
    return {
      valid: false,
      projectId: projectId || 'missing',
      databaseId: databaseId || 'missing',
      errorCode: 'wrong_firestore_database',
      reason: `Invalid or missing Firebase projectId "${projectId || 'empty'}". Expected "${EXPECTED_FIREBASE_PROJECT_ID}".`,
    };
  }

  if (!databaseId || databaseId === '(default)') {
    return {
      valid: false,
      projectId,
      databaseId: databaseId || '(default)',
      errorCode: 'wrong_firestore_database',
      reason: `Invalid Firestore database target "${databaseId || '(default)'}". BioGuard X requires the explicit named database "${EXPECTED_FIRESTORE_DATABASE_ID}".`,
    };
  }

  return { valid: true, projectId, databaseId };
}

const REDACTED_KEYS = new Set([
  'embedding',
  'embeddings',
  'vector',
  'vectors',
  'samples',
  'template',
  'templates',
  'minutiae',
  'encryptedpayload',
  'ciphertext',
  'idtoken',
  'token',
  'accesstoken',
  'refreshtoken',
  'authorization',
  'secret',
  'password',
  'privatekey',
  'serviceaccount',
  'apikey',
]);

export function sanitizeDiagnosticPayload<T = unknown>(value: T, depth = 0): T {
  if (depth > 4) return '[Truncated]' as unknown as T;
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (/^Bearer\s+/i.test(value) || /^eyJ[a-zA-Z0-9_-]{10,}\./.test(value)) {
      return '[REDACTED_TOKEN]' as unknown as T;
    }
    return (value.length > 320 ? `${value.slice(0, 320)}...` : value) as unknown as T;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    if (value.length > 25 && value.every((item) => typeof item === 'number')) {
      return `[REDACTED_VECTOR(${value.length})]` as unknown as T;
    }
    return value.slice(0, 20).map((item) => sanitizeDiagnosticPayload(item, depth + 1)) as unknown as T;
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const normalized = k.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (REDACTED_KEYS.has(normalized)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = sanitizeDiagnosticPayload(v, depth + 1);
      }
    }
    return out as unknown as T;
  }
  return String(value) as unknown as T;
}

export interface DiagnosticContext {
  code?: string;
  rawCode?: string;
  operationStage?: string;
  operationType?: string;
  path?: string;
  httpStatus?: number;
  message?: string;
  projectId?: string;
  databaseId?: string;
  configValid?: boolean;
  isAuthenticated?: boolean;
  emailVerified?: boolean;
  isBootstrapAdmin?: boolean;
  userDocExists?: boolean | null;
  userRole?: string | null;
  userStatus?: string | null;
  identityExists?: boolean | null;
  identityStatus?: string | null;
  identityRefMatches?: boolean | null;
  schemaValid?: boolean | null;
  schemaErrors?: string[];
}

export interface ClassifiedDiagnostic {
  diagnosticCode: DiagnosticCategory;
  diagnosticCategory: DiagnosticCategory;
  diagnosticTitle: string;
  diagnosticExplanation: string;
  diagnosticRemediation: string;
  httpStatus: number;
  projectId: string;
  databaseId: string;
}

export function isBootstrapAdminEmail(email: unknown, emailVerified: boolean | null | undefined): boolean {
  return (
    emailVerified === true &&
    typeof email === 'string' &&
    email.trim().toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL
  );
}

export function classifyFirestoreDiagnostic(ctx: DiagnosticContext): ClassifiedDiagnostic {
  const projectId = ctx.projectId || EXPECTED_FIREBASE_PROJECT_ID;
  const databaseId = ctx.databaseId || EXPECTED_FIRESTORE_DATABASE_ID;
  const code = String(ctx.code || '').toLowerCase();
  const rawCode = String(ctx.rawCode || '').toLowerCase();
  const stage = String(ctx.operationStage || '').toLowerCase();
  const msg = String(ctx.message || '');
  const lowerMsg = msg.toLowerCase();

  const build = (
    diagnosticCode: DiagnosticCategory,
    diagnosticTitle: string,
    diagnosticExplanation: string,
    diagnosticRemediation: string,
    httpStatus: number
  ): ClassifiedDiagnostic => ({
    diagnosticCode,
    diagnosticCategory: diagnosticCode,
    diagnosticTitle,
    diagnosticExplanation,
    diagnosticRemediation,
    httpStatus,
    projectId,
    databaseId,
  });

  // 1. Config / Database target errors
  if (
    ctx.configValid === false ||
    databaseId === '(default)' ||
    code === 'wrong_firestore_database' ||
    code === 'firestore_database_not_found' ||
    code === 'firestore_config_invalid' ||
    /database .* does not exist|database .* not found/i.test(msg)
  ) {
    return build(
      'wrong_firestore_database',
      'Wrong or Unreachable Firestore Named Database',
      `Targeted Firestore database "${databaseId}" in project "${projectId}" could not be resolved or is misconfigured.`,
      `Ensure firebase-applet-config.json, firebase.json, and server configuration all point to project "${EXPECTED_FIREBASE_PROJECT_ID}" and named database "${EXPECTED_FIRESTORE_DATABASE_ID}".`,
      503
    );
  }

  // 1b. Backend biometric vault decryption / legacy key mismatch (must run before generic BIOGUARD_VAULT_SECRET text match)
  if (
    code === 'vault_decryption_failed' ||
    code === 'vault_record_corrupt' ||
    stage === 'vault_decryption'
  ) {
    return build(
      'vault_decryption_failed',
      'Biometric Vault Legacy Record Mismatch',
      msg || 'This stored biometric record was encrypted with an obsolete vault key and cannot be unlocked.',
      'Click "Re-Enroll & Reset" below to overwrite this identity with a fresh template using the built-in app encryption, or delete the old record from Identities.',
      ctx.httpStatus || 422
    );
  }

  // 1c. Legacy vault secret configuration error (should no longer occur with app-managed vault)
  if (
    code === 'vault_secret_not_configured' ||
    stage === 'vault_configuration' ||
    /bioguard_vault_secret/i.test(lowerMsg)
  ) {
    return build(
      'vault_secret_not_configured',
      'Biometric Vault Service Unavailable',
      msg || 'The backend API server could not initialize biometric vault encryption.',
      'Refresh the page or restart the backend server to re-initialize the built-in app vault.',
      ctx.httpStatus || 503
    );
  }

  // 1d. Backend biometric vault persistence / read-back errors
  if (code === 'vault_readback_failed' || code === 'vault_delete_verification_failed') {
    return build(
      'vault_storage_error',
      'Biometric Vault Read-Back Verification Failed',
      msg || `Biometric vault persistence check failed at path "${ctx.path || 'biometric_vault'}".`,
      `Verify connectivity and deployed firestore.rules on project "${projectId}" database "${databaseId}", then retry the operation.`,
      ctx.httpStatus || 500
    );
  }

  // 2. Network / Offline / Unavailable errors
  if (
    code === 'network_failure' ||
    code === 'firestore_unreachable' ||
    code === 'auth_service_unavailable' ||
    code === 'authorization_unavailable' ||
    code === 'firestore_unavailable' ||
    code === 'firestore_deadline_exceeded' ||
    rawCode === 'unavailable' ||
    rawCode === 'deadline-exceeded' ||
    /client is offline|network error|network failure|failed to fetch|timed out|timeout|econnrefused|enotfound/i.test(lowerMsg)
  ) {
    return build(
      'network_failure',
      'Network or Upstream Service Unreachable',
      `Could not reach BioGuard X backend or Firestore database "${databaseId}" due to a network timeout or offline connection.`,
      'Check network connectivity, CORS/firewall settings, and try the operation again.',
      503
    );
  }

  // 3. Unauthenticated session
  if (
    ctx.isAuthenticated === false ||
    code === 'unauthenticated' ||
    code === 'missing_uid' ||
    code === 'missing_token' ||
    code === 'invalid_token' ||
    code === 'firestore_unauthenticated' ||
    rawCode === 'unauthenticated' ||
    ctx.httpStatus === 401
  ) {
    if (
      stage === 'firebase_id_token_lookup' ||
      code === 'invalid_credentials' ||
      code === 'missing_token' ||
      code === 'invalid_token'
    ) {
      return build(
        'backend_auth_failure',
        'Backend Firebase Token Verification Failed',
        'The backend API rejected or could not verify your Firebase ID token against Google Identity Toolkit.',
        'Sign out and sign back in with Google so a fresh Firebase ID token is issued.',
        401
      );
    }
    return build(
      'unauthenticated',
      'Authentication Session Missing or Expired',
      'No active Firebase Authentication session was present when accessing Firestore.',
      'Sign in with Google and retry.',
      401
    );
  }

  // 4. Backend auth failure explicitly signaled
  if (stage === 'firebase_id_token_lookup' || code === 'invalid_credentials' || code === 'backend_auth_failure') {
    return build(
      'backend_auth_failure',
      'Backend Firebase Token Verification Failed',
      msg || 'The backend API rejected the Bearer Firebase ID token.',
      'Sign out and sign back in with Google to refresh your ID token.',
      401
    );
  }

  // 5. Email not verified
  if (ctx.emailVerified === false || code === 'email_not_verified' || stage === 'email_verification') {
    return build(
      'email_not_verified',
      'Verified Email Required',
      'Firebase Auth token does not have email_verified=true. Both firestore.rules and the backend require a verified Google email.',
      'Sign in using a verified Google account.',
      403
    );
  }

  // 6. Client pre-write schema validation failure
  if (
    ctx.schemaValid === false ||
    code === 'verification_record_schema_invalid' ||
    code === 'invalid_identity_ref' ||
    code === 'invalid_modalities' ||
    code === 'invalid_outcome' ||
    stage === 'verification_record_validation'
  ) {
    const detail = ctx.schemaErrors?.length ? ` (${ctx.schemaErrors.join('; ')})` : '';
    return build(
      'verification_record_schema_invalid',
      'Verification Record Schema Validation Error',
      `Verification record payload failed pre-write validation against firestore.rules constraints${detail}.`,
      'Inspect field types, allowed keys, and ranges in src/shared/verificationRecord.ts.',
      400
    );
  }

  // 7. Account suspended (before role/profile checks)
  if (ctx.userStatus === 'suspended' || code === 'account_suspended' || stage === 'account_status') {
    return build(
      'account_suspended',
      'Operator Account Suspended',
      `User workspace profile at "users/{uid}" has status="suspended", which blocks writes in firestore.rules and backend routes.`,
      'Contact a super_admin to reactivate the user status to "active".',
      403
    );
  }

  // 8. Missing user workspace profile
  if (code === 'user_profile_missing' || (ctx.userDocExists === false && !ctx.isBootstrapAdmin)) {
    return build(
      'user_profile_missing',
      'User Workspace Profile Missing in Firestore',
      `No workspace profile document exists at "users/{uid}" in database "${databaseId}". Non-bootstrap accounts require an active non-viewer profile document.`,
      'Reload the session or re-authenticate so provisionUserProfile creates your /users/{uid} profile.',
      403
    );
  }

  // 9. Unauthorized role
  if (
    code === 'unauthorized_role' ||
    code === 'forbidden' ||
    stage === 'capability_check' ||
    (!ctx.isBootstrapAdmin && ctx.userRole === 'viewer')
  ) {
    return build(
      'unauthorized_role',
      'Role Lacks Workspace Write Permission',
      `Account role "${ctx.userRole || 'viewer'}" does not permit creating biometric verification records (firestore.rules requires role != "viewer" or bootstrap admin).`,
      'Request an administrator to grant operator, security_analyst, or administrator permissions.',
      403
    );
  }

  // 10. Identity metadata missing or inactive
  if (ctx.identityExists === false || code === 'identity_metadata_missing') {
    return build(
      'identity_metadata_missing',
      'Claimed Identity Metadata Missing in Firestore',
      `Referenced identity document was not found at "${ctx.path || 'users/{uid}/identities/{identityRef}'}". firestore.rules requires the identity document to exist and be active.`,
      'Re-enroll the identity in Enrollment so its Firestore identity metadata and vault entry are synchronized.',
      403
    );
  }

  if (
    code === 'identity_inactive' ||
    code === 'identity_ref_mismatch' ||
    (ctx.identityStatus && ctx.identityStatus !== 'active') ||
    ctx.identityRefMatches === false
  ) {
    return build(
      'identity_inactive',
      'Claimed Identity Is Inactive or Mismatched',
      `Referenced identity status is "${ctx.identityStatus || 'inactive'}" or its identityRef field disagrees with its document ID. firestore.rules only allows verification records for active identities.`,
      'Activate the identity in the Identities directory before running verification.',
      403
    );
  }

  // 10b. Missing vault template or feature version mismatch (HTTP 404/409/422)
  if (code === 'missing_identity' || code === 'not_found') {
    return build(
      'missing_vault_template',
      'Biometric Template Missing in Encrypted Vault',
      msg || 'No encrypted biometric template exists in the backend vault for this identity.',
      'Re-enroll the identity in Guided Biometric Enrollment so its AES-256-GCM vault template and Firestore metadata are synchronized.',
      ctx.httpStatus || 404
    );
  }

  if (code === 'feature_version_mismatch' || code === 'no_compatible_modalities') {
    return build(
      'feature_version_mismatch',
      'Incompatible Biometric Feature Version or Modalities',
      msg || 'Enrolled template version or modalities are incompatible with this verification or comparison request.',
      'Re-enroll the affected identity with current extractors or choose modalities shared by the enrolled profile.',
      ctx.httpStatus || 409
    );
  }

  // 10c. Biometric quality gates, sample validation, rate limits, CORS, and AI Analyst
  if (code === 'quality_check_failed') {
    return build(
      'biometric_quality_rejected',
      'Biometric Sample Quality Gate Rejected',
      msg || 'Captured or uploaded biometric sample did not meet minimum quality thresholds.',
      'Recapture in better lighting/focus (face), quiet speech >=0.8s (voice), or higher-contrast ridge print >=96x96px (fingerprint).',
      ctx.httpStatus || 422
    );
  }

  if (
    code === 'invalid_face_sample' ||
    code === 'invalid_voice_sample' ||
    code === 'invalid_fingerprint_sample' ||
    code === 'invalid_probe_sample' ||
    code === 'no_modalities_provided' ||
    code === 'missing_template_or_sample' ||
    code === 'missing_face_modality' ||
    code === 'same_identity_comparison_not_allowed' ||
    code === 'consent_required' ||
    code === 'duplicate_request_replay' ||
    code === 'invalid_display_name' ||
    code === 'invalid_biometric_parameters' ||
    code === 'invalid_role' ||
    code === 'invalid_uid' ||
    code === 'self_suspend_blocked' ||
    code === 'empty_update'
  ) {
    return build(
      'biometric_sample_invalid',
      'Biometric Request Validation Failed',
      msg || 'Biometric sample or request parameters failed backend validation.',
      'Verify all required modalities, consent checkbox, and probe capture quality before resubmitting.',
      ctx.httpStatus || 422
    );
  }

  if (code === 'rate_limit_exceeded' || ctx.httpStatus === 429) {
    return build(
      'rate_limited',
      'Request Rate Limit Exceeded',
      msg || 'Too many requests were submitted in a short window.',
      'Wait briefly before retrying the operation.',
      429
    );
  }

  if (code === 'rate_limiter_unavailable') {
    return build(
      'rate_limiter_unavailable',
      'Distributed Rate Limiter Unavailable',
      msg || `Persistent Firestore rate limiter at "${ctx.path || 'users/{uid}/rate_limits'}" could not be updated.`,
      `Confirm firestore.rules allow rate_limits writes on "${databaseId}" and retry.`,
      ctx.httpStatus || 503
    );
  }

  if (code === 'cors_origin_denied') {
    return build(
      'cors_origin_denied',
      'Request Origin Not Permitted by CORS Policy',
      msg || 'The backend rejected this request Origin header.',
      'Ensure ALLOWED_ORIGINS includes your frontend deployment URL.',
      403
    );
  }

  if (
    code === 'gemini_not_configured' ||
    code === 'gemini_request_failed' ||
    code === 'empty_model_response' ||
    code === 'invalid_prompt'
  ) {
    return build(
      'ai_service_unavailable',
      'AI Security Analyst Service Unavailable',
      msg || 'The Gemini AI Security Analyst could not complete the request.',
      'Verify GEMINI_API_KEY in server environment variables and retry.',
      ctx.httpStatus || 503
    );
  }

  // 11. Permission denied when all preconditions were verified -> undeployed or outdated firestore.rules on the named DB!
  const isPermDenied =
    rawCode === 'permission-denied' ||
    code === 'firestore_permission_denied' ||
    code === 'undeployed_or_outdated_security_rules' ||
    ctx.httpStatus === 403 ||
    /missing or insufficient permissions|permission_denied/i.test(lowerMsg);

  if (isPermDenied) {
    const hasWritePrivilege =
      Boolean(ctx.isBootstrapAdmin) ||
      (ctx.userDocExists === true && ctx.userStatus === 'active' && Boolean(ctx.userRole) && ctx.userRole !== 'viewer');
    const identityReady =
      stage !== 'verification_record_creation' ||
      (ctx.identityExists === true && ctx.identityStatus === 'active' && ctx.identityRefMatches === true);

    if (
      ctx.isAuthenticated === true &&
      ctx.emailVerified === true &&
      hasWritePrivilege &&
      identityReady
    ) {
      return build(
        'undeployed_or_outdated_security_rules',
        'Deployed Firestore Security Rules Are Missing or Outdated',
        `All client & workspace preconditions passed (verified email, ${ctx.isBootstrapAdmin ? 'bootstrapped super_admin' : `active ${ctx.userRole || 'operator'}`}, active identity, valid 46-field VerificationRecord schema, named database "${databaseId}"), yet Firestore rejected the write with PERMISSION_DENIED. Vercel deployments do not deploy firestore.rules—the ruleset live on "${databaseId}" is likely older than the repository's firestore.rules.`,
        `Deploy firestore.rules to project "${projectId}" database "${databaseId}" via "npm run deploy:rules", GitHub Actions "Deploy Firestore Rules", or Firebase DeployRules, then retry Verify Identity.`,
        403
      );
    }

    return build(
      'firestore_permission_denied',
      'Firestore Security Rules Denied Request',
      `Firestore rejected "${ctx.operationType || 'write'}" at "${ctx.path || 'unknown'}" in database "${databaseId}" (PERMISSION_DENIED).`,
      `Verify user authentication/role, referenced identity status, and confirm firestore.rules has been deployed to named database "${databaseId}".`,
      403
    );
  }

  const isFirestoreContext =
    rawCode.startsWith('firestore') ||
    code.startsWith('firestore_') ||
    /firestore|users\/|biometric_vault|verification_records|rate_limits/i.test(String(ctx.path || '')) ||
    /verification_record|identity_enrollment|identity_lookup|audit_logging|workspace_policy/i.test(stage);

  if (!isFirestoreContext && ctx.httpStatus && ctx.httpStatus >= 400) {
    return build(
      'api_request_error',
      'Backend API Request Failed',
      msg || `API request failed (${ctx.httpStatus}).`,
      'Review the request details, backend logs, and server configuration before retrying.',
      ctx.httpStatus
    );
  }

  return build(
    'firestore_permission_denied',
    'Firestore Operation Failed',
    msg || `Operation "${ctx.operationType || 'write'}" at "${ctx.path || 'unknown'}" failed.`,
    'Check browser console diagnostics and Firebase configuration.',
    ctx.httpStatus || 500
  );
}

// Pure TS policy evaluator mirroring firestore.rules `match /users/{userId}/verification_records/{verificationId} allow create`
export interface RuleAuthContext {
  uid: string;
  email?: string;
  email_verified?: boolean;
}

export interface RuleUserProfileDoc {
  uid: string;
  role: string;
  status: string;
}

export interface RuleIdentityDoc {
  identityRef: string;
  status: string;
}

export interface EvaluateVerificationCreateRuleInput {
  auth: RuleAuthContext | null;
  pathUserId: string;
  pathVerificationId: string;
  resourceData: Record<string, unknown>;
  requestTimeSentinel: unknown;
  userDoc?: RuleUserProfileDoc | null;
  identityDoc?: RuleIdentityDoc | null;
  /** Optional override simulating an outdated deployed ruleset with a smaller hasOnly() key allowlist */
  deployedAllowedKeysOverride?: readonly string[];
}

export interface EvaluateVerificationCreateRuleResult {
  allowed: boolean;
  deniedReasons: string[];
}

const MODALITY_SET = new Set<string>(VERIFICATION_SUPPORTED_MODALITIES);

export function evaluateVerificationRecordCreateRule(
  input: EvaluateVerificationCreateRuleInput
): EvaluateVerificationCreateRuleResult {
  const deniedReasons: string[] = [];
  const { auth, pathUserId, pathVerificationId, resourceData: data, requestTimeSentinel, userDoc, identityDoc } = input;

  const isValidId = (id: unknown): id is string =>
    typeof id === 'string' && VALID_FIRESTORE_ID_RE.test(id);

  if (!isValidId(pathUserId)) deniedReasons.push('Invalid path userId');
  if (!isValidId(pathVerificationId)) deniedReasons.push('Invalid path verificationId');
  if (!auth || !auth.uid) {
    deniedReasons.push('request.auth == null (unauthenticated)');
    return { allowed: false, deniedReasons };
  }
  if (auth.email_verified !== true) {
    deniedReasons.push('request.auth.token.email_verified != true');
  }
  if (auth.uid !== pathUserId) {
    deniedReasons.push('isOwner(userId) failed (auth.uid != userId)');
  }

  // canWriteOwnWorkspace(userId)
  const isBootstrap = isBootstrapAdminEmail(auth.email, auth.email_verified);
  const isOwnWorkspace = auth.uid === pathUserId;
  const activeNonViewerProfile =
    Boolean(userDoc) && userDoc?.status === 'active' && userDoc?.role !== 'viewer';
  if (!((isBootstrap && isOwnWorkspace) || activeNonViewerProfile)) {
    if (!userDoc && !isBootstrap) deniedReasons.push('canWriteOwnWorkspace: users/{uid} profile missing');
    else if (userDoc?.status !== 'active' && !(isBootstrap && isOwnWorkspace)) {
      deniedReasons.push(`canWriteOwnWorkspace: account status="${userDoc?.status}" != active`);
    } else if (userDoc?.role === 'viewer' && !(isBootstrap && isOwnWorkspace)) {
      deniedReasons.push('canWriteOwnWorkspace: role == viewer cannot write workspace');
    } else {
      deniedReasons.push('canWriteOwnWorkspace failed');
    }
  }

  // isValidVerificationRecord(incoming())
  const keys = Object.keys(data);
  const allowedSet = new Set<string>(input.deployedAllowedKeysOverride ?? VERIFICATION_RECORD_ALLOWED_KEYS);

  for (const reqKey of VERIFICATION_RECORD_REQUIRED_KEYS) {
    if (!(reqKey in data) || data[reqKey] === undefined) {
      deniedReasons.push(`Missing required key "${reqKey}"`);
    }
  }
  for (const key of keys) {
    if (!allowedSet.has(key)) {
      deniedReasons.push(`Key "${key}" is not allowed by hasOnly([...])`);
    }
  }

  if (!isValidId(data.verificationId)) deniedReasons.push('Invalid verificationId format');
  if (data.verificationId !== pathVerificationId) {
    deniedReasons.push('incoming().verificationId != verificationId path parameter');
  }
  if (typeof data.identityRef !== 'string' || !VALID_IDENTITY_REF_RE.test(data.identityRef)) {
    deniedReasons.push('Invalid identityRef format');
  }
  if (
    !Array.isArray(data.modalities) ||
    data.modalities.length < 1 ||
    data.modalities.length > 3 ||
    typeof data.modalities[0] !== 'string' ||
    data.modalities.some((m) => typeof m !== 'string' || !MODALITY_SET.has(m))
  ) {
    deniedReasons.push('Invalid modalities list');
  }
  if ('pipeline' in data && (typeof data.pipeline !== 'string' || data.pipeline.length < 1 || data.pipeline.length > 64)) {
    deniedReasons.push('Invalid pipeline');
  }
  if (!['match', 'no_match', 'not_evaluated'].includes(String(data.outcome))) {
    deniedReasons.push('Invalid outcome');
  }
  if ('finalDecision' in data && !['VERIFIED', 'REJECTED', 'INCONCLUSIVE'].includes(String(data.finalDecision))) {
    deniedReasons.push('Invalid finalDecision');
  }
  if (data.policyDecision !== 'pending') {
    deniedReasons.push('policyDecision != "pending"');
  }
  if (typeof data.reasonCode !== 'string' || data.reasonCode.length < 1 || data.reasonCode.length > 80) {
    deniedReasons.push('Invalid reasonCode');
  }

  const checkNum = (field: string, min: number, max?: number) => {
    if (!(field in data)) return;
    const v = data[field];
    if (typeof v !== 'number' || !Number.isFinite(v) || v < min || (max !== undefined && v > max)) {
      deniedReasons.push(`Field "${field}" failed numeric check`);
    }
  };
  checkNum('score', 0, 1);
  checkNum('riskScore', 0, 100);
  checkNum('livenessScore', 0, 1);
  checkNum('processingTimeMs', 0, 120000);
  checkNum('confidence', 0, 1);
  checkNum('identityConfidence', 0, 1);
  checkNum('sampleQualityScore', 0, 1);
  checkNum('livenessConfidence', 0, 1);
  checkNum('faceScore', 0, 1);
  checkNum('voiceScore', 0, 1);
  checkNum('fingerprintScore', 0, 1);
  checkNum('faceQuality', 0, 100);
  checkNum('voiceQuality', 0, 100);
  checkNum('fingerprintQuality', 0, 100);
  checkNum('matchedMinutiae', 0);
  checkNum('probeMinutiae', 0);

  if ('riskLevel' in data && !['low', 'medium', 'high', 'critical'].includes(String(data.riskLevel))) {
    deniedReasons.push('Invalid riskLevel');
  }
  if (
    'livenessStatus' in data &&
    !['LIVENESS PASSED', 'LIVENESS FAILED', 'INCONCLUSIVE', 'NOT SUPPORTED'].includes(String(data.livenessStatus))
  ) {
    deniedReasons.push('Invalid livenessStatus');
  }
  if ('livenessDecision' in data && !['PASSED', 'FAILED', 'INCONCLUSIVE'].includes(String(data.livenessDecision))) {
    deniedReasons.push('Invalid livenessDecision');
  }
  if ('groundTruth' in data && !['genuine', 'impostor', 'unlabeled'].includes(String(data.groundTruth))) {
    deniedReasons.push('Invalid groundTruth');
  }
  if ('datasetCategory' in data && !['operational', 'synthetic_qa', 'benchmark_eval'].includes(String(data.datasetCategory))) {
    deniedReasons.push('Invalid datasetCategory');
  }
  if ('confidenceBand' in data && !['high', 'moderate', 'low'].includes(String(data.confidenceBand))) {
    deniedReasons.push('Invalid confidenceBand');
  }
  for (const modField of ['faceStatus', 'voiceStatus', 'fingerprintStatus'] as const) {
    if (
      modField in data &&
      !['MATCH', 'NO MATCH', 'INCONCLUSIVE', 'NOT EVALUATED'].includes(String(data[modField]))
    ) {
      deniedReasons.push(`Invalid ${modField}`);
    }
  }
  if ('partition' in data && data.partition !== 'eval' && data.partition !== 'unassigned') {
    deniedReasons.push('Invalid partition');
  }
  for (const boolField of [
    'livenessPassed',
    'challengeVerified',
    'adaptiveApplied',
    'isTestProbe',
    'captureFailure',
    'conflictDetected',
  ] as const) {
    if (boolField in data && typeof data[boolField] !== 'boolean') {
      deniedReasons.push(`Field "${boolField}" must be bool`);
    }
  }
  const checkStr = (field: string, maxLen: number) => {
    if (!(field in data)) return;
    const v = data[field];
    if (typeof v !== 'string' || v.length < 1 || v.length > maxLen) {
      deniedReasons.push(`Field "${field}" failed string length check`);
    }
  };
  checkStr('featureVersion', 32);
  checkStr('subjectKey', 80);
  checkStr('sampleHash', 128);
  checkStr('benchmarkBatchId', 80);
  checkStr('provenanceSignature', 160);

  if (data.operatorUid !== auth.uid) {
    deniedReasons.push('operatorUid != request.auth.uid');
  }
  if (data.createdAt !== requestTimeSentinel) {
    deniedReasons.push('createdAt != request.time (forged client timestamp rejected)');
  }

  // Identity existence + active status + matching identityRef
  if (!identityDoc) {
    deniedReasons.push('users/{userId}/identities/{identityRef} does not exist');
  } else {
    if (identityDoc.status !== 'active') {
      deniedReasons.push(`Identity status="${identityDoc.status}" != active`);
    }
    if (identityDoc.identityRef !== data.identityRef) {
      deniedReasons.push('Identity identityRef field mismatch');
    }
  }

  return {
    allowed: deniedReasons.length === 0,
    deniedReasons,
  };
}

export interface FirebaseAuthDiagnostic {
  code: string;
  title: string;
  explanation: string;
  remediation: string;
  hostname: string;
  authDomain: string;
  formattedMessage: string;
}

export function formatFirebaseAuthDiagnostic(
  error: unknown,
  currentHostname?: string,
  configuredAuthDomain?: string
): FirebaseAuthDiagnostic {
  const errObj = (error && typeof error === 'object' ? error : {}) as { code?: unknown; message?: unknown };
  const rawCode = String(errObj.code || '').trim();
  const rawMsg = error instanceof Error ? error.message : String(errObj.message || error || 'Google Sign-In failed.');
  const hostname = String(currentHostname || '').trim() || 'current-host';
  const authDomain = String(configuredAuthDomain || '').trim() || `${EXPECTED_FIREBASE_PROJECT_ID}.firebaseapp.com`;

  if (rawCode === 'auth/unauthorized-domain' || /unauthorized[-_ ]domain/i.test(rawMsg)) {
    const title = 'Firebase Auth Domain Not Authorized (auth/unauthorized-domain)';
    const explanation = `Google Sign-In was blocked because "${hostname}" is not listed under Authorized Domains for Firebase project "${EXPECTED_FIREBASE_PROJECT_ID}" (authDomain: "${authDomain}").`;
    const remediation = `Open Firebase Console -> Project "${EXPECTED_FIREBASE_PROJECT_ID}" -> Authentication -> Settings -> Authorized domains -> Add domain "${hostname}" (along with localhost and any Vercel/Cloud Run preview hostnames), then reload and sign in again.`;
    return {
      code: 'auth/unauthorized-domain',
      title,
      explanation,
      remediation,
      hostname,
      authDomain,
      formattedMessage: `${title}\n${explanation}\nHow to fix: ${remediation}`,
    };
  }

  if (rawCode === 'auth/popup-closed-by-user') {
    const title = 'Sign-In Popup Closed';
    const explanation = 'The Google Sign-In popup window was closed before authentication completed.';
    const remediation = 'Click "Sign in with Google" and finish selecting your verified Google account.';
    return {
      code: rawCode,
      title,
      explanation,
      remediation,
      hostname,
      authDomain,
      formattedMessage: `${title}: ${explanation} ${remediation}`,
    };
  }

  if (rawCode === 'auth/popup-blocked') {
    const title = 'Google Sign-In Popup Blocked';
    const explanation = `The browser blocked the Google Sign-In popup window on "${hostname}".`;
    const remediation = 'Allow popups for this site or open BioGuard X directly in a standalone browser tab and sign in again.';
    return {
      code: rawCode,
      title,
      explanation,
      remediation,
      hostname,
      authDomain,
      formattedMessage: `${title}: ${explanation} ${remediation}`,
    };
  }

  if (rawCode === 'auth/web-storage-unsupported' || rawCode === 'auth/operation-not-supported-in-this-environment') {
    const title = 'Browser Storage Restricted for Sign-In';
    const explanation = `Third-party cookies or web storage required by Firebase Auth popup are restricted on "${hostname}".`;
    const remediation = 'Open BioGuard X in a new browser tab or enable cookies/storage for this site, then sign in with Google.';
    return {
      code: rawCode,
      title,
      explanation,
      remediation,
      hostname,
      authDomain,
      formattedMessage: `${title}: ${explanation} ${remediation}`,
    };
  }

  if (rawCode === 'auth/cancelled-popup-request') {
    const title = 'Previous Sign-In Request Cancelled';
    const explanation = 'Another Google Sign-In request superseded the previous popup attempt.';
    const remediation = 'Complete the sign-in flow in the active Google popup window or try again.';
    return {
      code: rawCode,
      title,
      explanation,
      remediation,
      hostname,
      authDomain,
      formattedMessage: `${title}: ${explanation} ${remediation}`,
    };
  }

  if (rawCode === 'auth/network-request-failed') {
    const title = 'Firebase Auth Network Failure';
    const explanation = 'The browser could not reach Firebase Authentication servers during Google Sign-In.';
    const remediation = 'Verify internet connectivity and ensure third-party popups/cookies are not blocked by browser extensions.';
    return {
      code: rawCode,
      title,
      explanation,
      remediation,
      hostname,
      authDomain,
      formattedMessage: `${title}: ${explanation} ${remediation}`,
    };
  }

  return {
    code: rawCode || 'auth/error',
    title: 'Google Sign-In Error',
    explanation: rawMsg,
    remediation: 'Retry Google Sign-In or check Firebase Authentication configuration.',
    hostname,
    authDomain,
    formattedMessage: rawMsg,
  };
}

