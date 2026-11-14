# Model card
Face: Haar detection -> CLAHE -> HOG (1764-D) / LBP (640-D); Voice: MFCC mean/std (40) + ZCR (2) + RMS (2) = 44-D; Fingerprint (optional): CLAHE -> Gabor -> HOG/LBP+minutiae counts.
Verifiers: pair classifiers on |a-b| (SVM-RBF, Random Forest, KNN) scored against the claimed user's enrolment samples; thresholds = validation EER point.
Fusion: early (separate scaling + 1/sqrt(dim) block weighting), score (grid-searched weight on validation), decision (AND/OR chosen on validation), hierarchical (face -> early fusion if uncertain).
Intended use: university research/demo. Limits: small custom datasets, enrolled-user (not participant-independent) verification, results depend on collection sessions; not production biometric security.
Actual numbers are produced by `scripts.run_all` into `reports/all_results.csv` (none are hard-coded).
