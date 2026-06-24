# SSL/TLS Analyser — PFE

Plateforme d'analyse de la posture SSL/TLS (Flask + SSLyze + Random Forest) : scan mono-port
et multi-port (STARTTLS), scoring IA des vulnérabilités, comparaison de scans, historique et
rapport PDF avec conformité PCI-DSS v4.0 / NIST SP 800-52.

---

## 1. Prérequis

```bash
# Dépendances (installées dans le .venv du projet)
pip install flask flask-sqlalchemy flask-bcrypt flask-wtf sslyze requests urllib3 \
            numpy scikit-learn reportlab pymysql weasyprint cryptography
# Dépendances de test :
pip install -r requirements-dev.txt
```

- **Base de données** : MySQL/MariaDB sur `localhost`, base `vulnerability_scanner`, user `root`
  sans mot de passe (voir `config.py`). L'app crée les tables au démarrage (`db.create_all()`).
  Si la base n'existe pas : `CREATE DATABASE vulnerability_scanner;`
- **WeasyPrint** (rapport PCI-DSS multi-port, Windows) : nécessite GTK — voir `CLAUDE.md`.
  Le rapport mono-port (ReportLab) fonctionne sans GTK.

---

## 2. Lancer l'application en HTTPS avec le cadenas « sécurisé » 🔒

Par défaut l'app génère un certificat **auto-signé** → le navigateur affiche « connexion non
sécurisée ». Pour obtenir le **cadenas vert**, on crée une petite **autorité (CA) locale**, on
l'installe **une seule fois** dans le magasin racine, puis on lance l'app.

> ⚠️ Étape 2 (installer la CA) : Windows **exige votre confirmation** pour ajouter une autorité
> racine — c'est une protection de sécurité, elle ne peut pas être automatisée silencieusement.

### Étape 1 — Générer le certificat signé par la CA locale
Depuis le dossier du projet :
```bash
python generer_cert_https.py
```
Cela écrit `cert.pem`, `key.pem` (lus par `app.py`) et **`ca-local.crt`** (la CA à installer).

### Étape 2 — Installer la CA dans « Autorités de certification racines de confiance »

**Méthode A — interface graphique (recommandée)**
1. Double-cliquer sur **`ca-local.crt`** (dans le dossier du projet).
2. Cliquer **« Installer un certificat… »**.
3. Emplacement du magasin : **Utilisateur actuel** → **Suivant**.
4. Cocher **« Placer tous les certificats dans le magasin suivant »** → **Parcourir…**
5. Choisir **« Autorités de certification racines de confiance »** → **OK** → **Suivant** → **Terminer**.
6. Une **alerte de sécurité** s'affiche → cliquer **Oui** (c'est notre CA locale).

**Méthode B — PowerShell (fenêtre interactive)**
```powershell
Import-Certificate -FilePath .\ca-local.crt -CertStoreLocation Cert:\CurrentUser\Root
# Cliquer « Oui » sur l'alerte de sécurité Windows.
```
Vérifier l'installation :
```powershell
Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'TLS Analyser Local CA' }
```

### Étape 3 — Lancer le serveur HTTPS
```bash
python app.py
```
Le serveur écoute sur **https://127.0.0.1:5000** (et **https://localhost:5000**).

### Étape 4 — Ouvrir dans le navigateur
1. **Fermer complètement** le navigateur puis le rouvrir (il relit le magasin racine au démarrage).
2. Aller sur **https://localhost:5000** → le **cadenas « sécurisé »** s'affiche, sans avertissement.

> Connexion par défaut : login **`fadwa`** / mot de passe **`fadwa123456`** (rôle Administrateur).

#### Dépannage
- Toujours « non sécurisé » ? Le navigateur n'a pas été redémarré après l'étape 2, ou l'URL est
  `https://127.0.0.1:5000` alors que le cache du navigateur garde l'ancienne exception — réessayer
  `https://localhost:5000` après redémarrage du navigateur.
- Régénérer un certificat (expiré, autre poste) : relancer `python generer_cert_https.py`,
  réinstaller `ca-local.crt`, redémarrer le navigateur.
- Le certificat serveur est valable **397 jours** (limite des navigateurs) ; la CA, 5 ans.

---

## 3. Composants de l'application

| Menu | Route | Description |
|---|---|---|
| Dashboard | `/dashboard` | Scan **mono-port** (443) : vulnérabilités, score TLS A–F, conformité, carte *Informatif* |
| Scan Multi-Port | `/multiport/lancer_scan_multiport` | Découverte des ports ouverts + scan TLS/STARTTLS, vue par port **et** agrégée + classement IA |
| Priorités IA | `/priorisation` | Vulnérabilités classées + remédiation par type de serveur |
| Historique | `/historique` | Scans passés ; détail multi-port en 3 catégories (TLS-OK / échec-TLS / non-TLS) |
| Comparaison | `/comparison/comparaison_scans` | Diff de 2 scans — **mono-port** et **multi-port** (5 états : corrigée/nouvelle/aggravée/améliorée/inchangée) |
| Exporter | `/rapport` | Rapport **PDF** mono-port (ReportLab) et multi-port (WeasyPrint) avec conformité PCI-DSS/NIST |

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
