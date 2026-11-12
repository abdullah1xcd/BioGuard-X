# BioGuard X Firestore Security Specification (Phase 0 TDD)

## 1. Core Data Invariants
1. **Deny-by-Default**: Unauthenticated requests and unknown collections are always rejected (`allow read, write: if false`).
2. **No Self-Privilege Escalation**: A newly signed-in user creating `/users/{uid}` can only assign `role == "viewer"` and `status == "active"`, unless their verified email matches the bootstrapped owner email. Users can never mutate their own `role` or `status`.
3. **PII Isolation**: `/users/{uid}` contains `email` and is readable only by the profile owner (`request.auth.uid == uid`) or an admin (`isAdmin()`).
4. **No Biometric Templates or Secrets in Firestore**: Encrypted templates, raw face/voice/fingerprint samples, and keys remain strictly in the server-side encrypted vault; schema `hasOnly` gates reject any shadow biometric fields.
5. **Immutable Audit & Verification Records**: `/audit_logs` and `/verification_records` cannot be updated or deleted by clients, and `policyDecision` on `/verification_records` is restricted to `"pending"` on client creation.
6. **Strict Server Timestamps & ID Validation**: Every `createdAt`, `updatedAt`, and `timestamp` must equal `request.time`. All document IDs are validated against `^[a-zA-Z0-9_\-]+$` with `size() <= 128`.
7. **Approval Workflow Integrity**: New `/approval_requests` documents must start with `status == "pending"`, reference an existing `/identities` document, and once resolved (`approved` or `rejected`) by an admin cannot be re-opened or mutated.

## 2. "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated read** on `/users/u1` -> `PERMISSION_DENIED`.
2. **Self-assigned admin role on signup**: `CREATE /users/u2` with `{ role: "super_admin" }` by non-bootstrapped user -> `PERMISSION_DENIED`.
3. **Role escalation update**: `UPDATE /users/u2` changing `role` from `"viewer"` to `"administrator"` by owner -> `PERMISSION_DENIED`.
4. **Cross-user PII read**: `GET /users/u1` by non-admin user `u2` -> `PERMISSION_DENIED`.
5. **Unverified email write**: `CREATE /identities/id1` when `request.auth.token.email_verified == false` -> `PERMISSION_DENIED`.
6. **Shadow biometric field injection**: `CREATE /identities/id1` containing `rawFaceVector: [0.1, ...]` -> `PERMISSION_DENIED` via `hasOnly`.
7. **Forged actorUid in audit log**: `CREATE /audit_logs/ev1` where `actorUid != request.auth.uid` -> `PERMISSION_DENIED`.
8. **Audit log tampering**: `UPDATE /audit_logs/ev1` or `DELETE /audit_logs/ev1` -> `PERMISSION_DENIED`.
9. **Client-forged timestamp**: `CREATE /verification_records/v1` with `createdAt: "2025-01-01T00:00:00Z"` instead of `request.time` -> `PERMISSION_DENIED`.
10. **Policy decision override**: `CREATE /verification_records/v1` with `policyDecision: "allow"` -> `PERMISSION_DENIED`.
11. **ID poisoning**: `CREATE /identities/../../evil` or 500-char document ID -> `PERMISSION_DENIED` via `isValidId()`.
12. **Blanket list scraping on notifications**: `LIST /notifications` by `u2` without `where('userUid', '==', 'u2')` -> `PERMISSION_DENIED`.
13. **Self-approved deletion request**: `CREATE /approval_requests/req1` with `status: "approved"` or `UPDATE /approval_requests/req1` by a non-admin requester -> `PERMISSION_DENIED`.
