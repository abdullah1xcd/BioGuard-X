# Security & privacy
* Biometric files stay on local disk; no cloud upload; SQLite stores references only.
* Consent required before enrolment; `delete_user` removes files + enrolment records, pseudonymises history; models trained earlier must be retrained.
* Identity (biometrics) -> risk/policy -> permission -> human approval -> action -> audit. Risk never grants access.
* Automation can only run allow-listed actions; sensitive actions need approval from an admin/manager; holds are time-limited (max 4 h); no permanent lockout.
* Threat model / known limits: the Streamlit operator login is NOT biometric-protected; photo/replay attacks are only partly mitigated by experimental classical checks;
  the spoken challenge does NOT recognise speech (segment-count heuristic + speaker verification); no encryption at rest (use OS disk encryption); single-machine SQLite.
* The optional LLM receives only pattern names and counts, never usernames or biometric data, and never decides.
