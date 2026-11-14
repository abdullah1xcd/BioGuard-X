# Installation (Windows 10/11, Python 3.12)
1. `py -3.12 -m venv .venv` then `.venv\Scripts\activate`
2. `pip install -r requirements.txt` (sounddevice is optional; needed only for server-side microphone recording)
3. Database: created automatically on first run (`data/bioguardx.db`); 11 default workflows are seeded.
4. Data: `datasets/custom/participant_XXX/...` (or enrol through the app's User Enrollment page).
5. Models: `python -m scripts.run_all` (creates `models/bioguard_bundle.joblib`, `reports/*`).
6. Launch: `streamlit run app/main.py`.
Optional LLM: install Ollama, `ollama pull llama3.2`, then enable it in Settings (explanations only).
