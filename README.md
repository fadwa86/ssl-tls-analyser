# SSL/TLS Analyser — PFE

Plateforme d'analyse de la posture SSL/TLS (Flask + SSLyze + Random Forest) : scan mono-port
et multi-port (STARTTLS), scoring IA des vulnérabilités, comparaison de scans, historique et
rapport PDF avec conformité PCI-DSS v4.0 / NIST SP 800-52.

---

## 1. Prérequis

```bash
# Dépendances (installées dans le .venv du projet)
pip install flask flask-sqlalchemy flask-bcrypt flask-wtf sslyze requests urllib3 \
            numpy scikit-learn reportlab pymysql cryptography cheroot
# Dépendances de test :
pip install -r requirements-dev.txt
```

- **Base de données** : MySQL/MariaDB sur `localhost`, base `vulnerability_scanner`, user `root`
  sans mot de passe (voir `config.py`). L'app crée les tables au démarrage (`db.create_all()`).
  Si la base n'existe pas : `CREATE DATABASE vulnerability_scanner;`
- **Rapports PDF** (mono-port **et** multi-port) : générés avec **ReportLab** — pur Python, aucune
  dépendance native (plus de WeasyPrint/GTK).

---

## 2. Lancer l'application

```bash
python app.py
```
Le serveur écoute sur **http://127.0.0.1:5000**, servi par **Cheroot** (serveur WSGI de
production) en **HTTP** — pas de rechargement automatique (relancer après modification).

> Connexion par défaut : login **`fadwa`** / mot de passe **`fadwa123456`** (rôle Administrateur).

---

## 3. Composants de l'application

| Menu | Route | Description |
|---|---|---|
| Dashboard | `/dashboard` | Scan **mono-port** (443) : vulnérabilités, grade TLS A–F, conformité, carte *Informatif* |
| Scan Multi-Port | `/multiport/lancer_scan_multiport` | Découverte des ports ouverts + scan TLS/STARTTLS, vue par port **et** agrégée + classement IA |
| Priorités IA | `/priorisation` | Vulnérabilités classées + remédiation par type de serveur |
| Historique | `/historique` | Scans passés ; détail multi-port en 3 catégories (TLS-OK / échec-TLS / non-TLS) |
| Comparaison | `/comparison/comparaison_scans` | Diff de 2 scans — **mono-port** et **multi-port** (5 états : corrigée/nouvelle/aggravée/améliorée/inchangée) |
| Exporter | `/rapport` | Rapport **PDF** mono-port **et** multi-port (ReportLab) avec conformité PCI-DSS/NIST |

**Règle de classement** : une vulnérabilité est *réelle* si elle porte un identifiant **CVE ou
CWE** (comptée, statut « Vulnérable », grade, score). Sans identifiant, elle est **Informatif**
(affichée partout avec une étiquette, mais non comptée). Les défauts de validité de certificat
(expiré, auto-signé, autorité non fiable, hôte invalide, chaîne incomplète) portent un **CWE** →
réels. SHA-1, no-SCT, suite anonyme, DES, downgrade restent informationnels.

---

## 4. Tests

```bash
# Suite hors-ligne (déterministe, CI)
python -m pytest -m "not network and not integration" -q

# Intégration live (réseau, opt-in) contre le corpus badssl
set TLS_LIVE=1 && python -m pytest tests/test_badssl_integration.py -m integration -v
```

Les cibles de test (badssl.com) vivent **uniquement** dans `tests/data/cibles_blueprint.py` — le
code du scanner (`agent_ia/`, `routes/`) ne contient aucun hôte de test.
