# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Flask web app that scans hosts for SSL/TLS vulnerabilities, scores each finding with a
Random Forest model, and produces prioritized reports. The codebase is in **French**
(identifiers, comments, DB columns — including accented names like `tls_preferé`). Keep new
code consistent with that.

## Commands

```bash
# Install deps (no requirements.txt exists — these are the actual imports)
pip install flask flask-sqlalchemy flask-bcrypt sslyze requests urllib3 numpy scikit-learn reportlab pymysql weasyprint
# WeasyPrint (rapport PCI-DSS multi-ports) needs GTK on Windows:
#   1) install MSYS2 (https://www.msys2.org)  2) MSYS2 shell: pacman -S mingw-w64-x86_64-pango
#   3) verify: python -m weasyprint --info   (routes/rapport.py auto-sets WEASYPRINT_DLL_DIRECTORIES if C:\msys64 exists)
# The single-port ReportLab report still works without WeasyPrint.

# Run (dev server, debug=True, http://127.0.0.1:5000)
python app.py

# Retrain the Random Forest model (rewrites agent_ia/modele_rf.pkl)
python -c "from agent_ia.modele_rf import entrainer_modele; entrainer_modele()"
```

- **No tests, no linter, no build step.** There is nothing to run for CI.
- On startup `app.py` runs `db.create_all()` and seeds a default admin: login `fadwa` /
  password `fadwa123456` (role `Administrateur`).

## Database gotcha

`config.py` points `SQLALCHEMY_DATABASE_URI` at **MySQL** (`vulnerability_scanner` DB on
`localhost`, user `root`, no password). The app will not start without that DB reachable.
There is also a leftover `instance/tls_analyzer.db` (SQLite) from an earlier config — it is
**not** used while `config.py` says MySQL. If switching back to SQLite, change the URI.

## Architecture

Blueprint-based Flask app. `app.py` registers everything; each `routes/*.py` is one blueprint.

**Scan pipeline** (`routes/scan.py`):
1. `agent_ia/scanner.py::scanner_cible` runs **SSLyze** against port 443 → raw dict
   (protocols enabled, Heartbleed, ROBOT, cert info, detected web server).
2. `agent_ia/agent.py::analyser_resultats` maps raw findings to known CVEs, **enriches each
   live** from NVD (CVSS) and FIRST (EPSS) APIs — see `get_metadata_temps_reel`, cached in
   `_cache_api` — then scores them.
3. `agent_ia/modele_rf.py::predire_score` (Random Forest) computes the criticité score from
   `[cvss, epss, type_encoded]`. Falls back to `(cvss*0.6)+(epss*4)` if the model fails.
4. Results persist to DB and to an **in-memory** `scans_en_cours` dict the frontend polls via
   `/scan_status/<id>`.

**Scoring invariant (important):** severity and priority are **never hardcoded**. The flow is
always `predire_score → determiner_severite → severite_vers_priorite`. Findings carry a CVSS
input only; the final severity comes out of the model. Preserve this when editing `agent.py`.

**ML model:** `entrainer_modele()` trains on a small hardcoded dataset embedded in
`modele_rf.py` (~40 rows of cvss/epss/type → criticité) and pickles it. `predire_score`
auto-retrains if `modele_rf.pkl` is missing. To change scoring behavior, edit the dataset and
retrain.

**Multi-port scan** (`routes/multiport_scan.py`, `agent_ia/scanner_multiport.py`,
`agent_ia/agent_multiport.py`): scans many service ports (SMTP/IMAP/POP3/FTP via STARTTLS,
plus HTTPS) and flags **TLS inconsistencies across ports** (e.g. port 25 weaker than 587).
This cross-port analysis is the project's intended differentiator over single-port scanners.

**Other blueprints:** `historique` (scan history), `priorisation` (ranked findings),
`comparison_bp` (diff two scans: fixed/new/unchanged), `rapport` (PDF generation via
reportlab), `profil`, `auth`.

## Conventions / things to know

- **Background scans run in threads.** Capture the app object before spawning
  (`app = current_app._get_current_object()`) and wrap the worker in `with app.app_context():`
  — see `routes/scan.py`. Status lives in a module-level dict, so it is lost on restart and
  not shared across worker processes.
- **Auth** is session-based (`session['admin_id']`), bcrypt-hashed passwords, with account
  lockout after 3 failed logins (`bloque`/`nb_tentatives` on `Administrateur`). Roles seen:
  `Administrateur`, `analyste` / `Analyste de sécurité`.
- All models live in one file: `models/models.py`.
- Templates are server-rendered Jinja in `templates/`.
