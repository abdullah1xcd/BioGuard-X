# BioGuard X Firestore Security Specification (Per-Account Isolation)

## 1. Core Data Invariants
1. **Deny-by-Default**: Unauthenticated requests and unknown collections are always rejected (`allow read, write: if false`).
2. **Strict Per-Google-Account Data Isolation**: All tenant operational collections (`identities`, `biometric_vault`, `verification_records`, `audit_logs`, `notifications`, `security_alerts`, `automation_workflows`, `system_settings`, `approval_requests`) live under `/users/{userId}/...` and require `request.auth.uid == userId` (`isOwner(userId)`), verified email (`email_verified == true`), and an active `/users/{userId}` account status.
3. **No Self-Privilege Escalation**: A newly signed-in Google user creating `/users/{uid}` can only assign `role == "operator"` (for their own isolated workspace) and `status == "active"`, unless their verified email matches the bootstrapped owner email. Users can never mutate their own `role` or `status`.
4. **PII Isolation**: `/users/{uid}` contains `email` and is readable only by the profile owner (`request.auth.uid == uid`) or an admin (`isAdmin()`).
5. **No Plaintext Biometric Templates in Firestore**: Encrypted templates remain strictly AES-256-GCM encrypted inside `/users/{uid}/biometric_vault/{identityRef}`; schema `hasOnly` gates reject any shadow biometric fields.
6. **Immutable Audit & Verification Records**: `/users/{uid}/audit_logs` and `/users/{uid}/verification_records` cannot be updated or deleted by clients, and `policyDecision` on `verification_records` is restricted to `"pending"` on client creation.
7. **Strict Server Timestamps & ID Validation**: Every `createdAt`, `updatedAt`, and `timestamp` must equal `request.time` (except server-written `biometric_vault.updatedAt` which requires `is timestamp`). All document IDs are validated against `^[a-zA-Z0-9_\-]+$` with `size() <= 128`.

## 2. "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated read** on `/users/u1` or `/users/u1/identities/id1` -> `PERMISSION_DENIED`.
2. **Cross-account read/list**: User `u2` reading or listing `/users/u1/identities` or `/users/u1/verification_records` -> `PERMISSION_DENIED`.
3. **Cross-account biometric vault access**: User `u2` reading or writing `/users/u1/biometric_vault/id1` -> `PERMISSION_DENIED`.
4. **Self-assigned admin role on signup**: `CREATE /users/u2` with `{ role: "super_admin" }` by non-bootstrapped user -> `PERMISSION_DENIED`.
5. **Role escalation update**: `UPDATE /users/u2` changing `role` from `"operator"` to `"administrator"` by owner -> `PERMISSION_DENIED`.
6. **Suspended account write**: User `u2` with `status == "suspended"` creating `/users/u2/identities/id1` -> `PERMISSION_DENIED`.
7. **Unverified email write**: `CREATE /users/u2/identities/id1` when `request.auth.token.email_verified == false` -> `PERMISSION_DENIED`.
8. **Shadow biometric field injection**: `CREATE /users/u2/identities/id1` containing `rawFaceVector: [0.1, ...]` -> `PERMISSION_DENIED` via `hasOnly`.
9. **Forged actorUid in audit log**: `CREATE /users/u2/audit_logs/ev1` where `actorUid != request.auth.uid` -> `PERMISSION_DENIED`.
10. **Audit log tampering**: `UPDATE` or `DELETE` on `/users/u2/audit_logs/ev1` -> `PERMISSION_DENIED`.
11. **Client-forged timestamp**: `CREATE /users/u2/verification_records/v1` with `createdAt: "2025-01-01T00:00:00Z"` instead of `request.time` -> `PERMISSION_DENIED`.
12. **ID poisoning**: `CREATE /users/u2/identities/../../evil` or 500-char document ID -> `PERMISSION_DENIED` via `isValidId()`.
