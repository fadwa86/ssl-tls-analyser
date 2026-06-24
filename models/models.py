from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()
#  AnalysteSécurité — classe de base (pas de table propre)
# ─────────────────────────────────────────────────────────────
class AnalysteSécurité:
    """Classe de base commune à tous les utilisateurs."""
    pass
#  Administrateur — hérite de AnalysteSécurité + db.Model
#  Table unique pour admins ET analystes de sécurité
class Administrateur(AnalysteSécurité, db.Model):
    __tablename__ = 'administrateur'
    id                 = db.Column(db.Integer, primary_key=True)
    nom                = db.Column(db.String(100))
    prenom             = db.Column(db.String(100))
    login              = db.Column(db.String(100), unique=True)
    password           = db.Column(db.String(200))
    email              = db.Column(db.String(100))
    role               = db.Column(db.String(50), nullable=False, default='Analyste de sécurité')
    date_creation      = db.Column(db.DateTime, default=datetime.now)   # ← nouveau
    derniere_connexion = db.Column(db.DateTime, nullable=True)              # ← nouveau
    bloque = db.Column(db.Boolean, default=False)
    nb_tentatives = db.Column(db.Integer, default=0)
    
class Cible(db.Model):
    __tablename__ = 'cible'
    id        = db.Column(db.Integer, primary_key=True)
    url       = db.Column(db.String(200))
    adresseIp = db.Column(db.String(100))
    dateAjout = db.Column(db.DateTime, default=datetime.now)

class Scan(db.Model):
    __tablename__ = 'scan'
    id                = db.Column(db.Integer, primary_key=True)
    cibleId           = db.Column(db.Integer, db.ForeignKey('cible.id'))
    adminId = db.Column(db.Integer, db.ForeignKey('administrateur.id'))
    administrateur_id = db.Column(db.Integer, db.ForeignKey('administrateur.id'), nullable=True)  # ← nouveau
    dateDebut         = db.Column(db.DateTime, default=datetime.now)
    dateFin           = db.Column(db.DateTime)
    statut            = db.Column(db.String(50))

class ResultatScan(db.Model):
    __tablename__ = 'resultat_scan'
    id              = db.Column(db.Integer, primary_key=True)
    scanId          = db.Column(db.Integer, db.ForeignKey('scan.id'))
    vulnerabiliteId = db.Column(db.Integer)
    donneesSSL      = db.Column(db.Text)
    dateAnalyse     = db.Column(db.DateTime, default=datetime.utcnow)

class Vulnerabilite(db.Model):
    __tablename__ = 'vulnerabilite'
    id          = db.Column(db.Integer, primary_key=True)
    nom         = db.Column(db.String(200))
    description = db.Column(db.Text)
    type        = db.Column(db.String(100))
    severite    = db.Column(db.String(50))
    cve         = db.Column(db.String(50))
    cvss        = db.Column(db.Float)
    epss        = db.Column(db.Float)
    criticite   = db.Column(db.Float)

class Priorisation(db.Model):
    __tablename__ = 'priorisation'
    id     = db.Column(db.Integer, primary_key=True)
    scanId = db.Column(db.Integer, db.ForeignKey('scan.id'))
    date   = db.Column(db.DateTime, default=datetime.now)

class Recommandation(db.Model):
    __tablename__ = 'recommandation'
    id              = db.Column(db.Integer, primary_key=True)
    description     = db.Column(db.Text)
    etapeCorrection = db.Column(db.Text)
    solution        = db.Column(db.Text)
    priorite        = db.Column(db.String(50))

class Rapport(db.Model):
    __tablename__ = 'rapport'
    id                = db.Column(db.Integer, primary_key=True)
    scanId            = db.Column(db.Integer, db.ForeignKey('scan.id'))
    administrateur_id = db.Column(db.Integer, db.ForeignKey('administrateur.id'), nullable=True)  # ← nouveau
    dateGeneration    = db.Column(db.DateTime, default=datetime.now)
    format            = db.Column(db.String(20))
    contenu           = db.Column(db.Text)
    cheminFichier     = db.Column(db.String(200))
    
class CibleMultiPort(db.Model):
    __tablename__ = 'cible_multiport'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(255), nullable=False)
    type_cible = db.Column(db.String(50), default='domaine')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ScanMultiPort(db.Model):
    __tablename__ = 'scan_multiport'
    id = db.Column(db.Integer, primary_key=True)
    cible_id = db.Column(db.Integer, db.ForeignKey('cible_multiport.id'), nullable=False)
    statut = db.Column(db.String(50), default='EN_COURS')
    score_risque_global = db.Column(db.Float, nullable=True)
    observation_ia = db.Column(db.Text, nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

class ResultatScanMultiPort(db.Model):
    __tablename__ = 'resultat_scan_multiport'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_multiport.id'), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocole = db.Column(db.String(50))
    starttls_utilise = db.Column(db.Boolean, default=False)
    tls_supported = db.Column(db.String(200))
    tls_preferé = db.Column(db.String(50))
    certificat_expiration = db.Column(db.DateTime, nullable=True)
    certificat_expire = db.Column(db.Boolean, default=False)
    certificat_valid = db.Column(db.Boolean, nullable=True)
    certificat_cn = db.Column(db.String(255), nullable=True)
    certificat_issuer = db.Column(db.Text, nullable=True)
    vuln_heartbleed = db.Column(db.Boolean, default=False)
    vuln_robot = db.Column(db.Boolean, default=False)
    vuln_ccs = db.Column(db.Boolean, default=False)
    vuln_ticketbleed = db.Column(db.Boolean, default=False)
    vuln_downgrade = db.Column(db.Boolean, default=False)
    suites_count = db.Column(db.Integer, nullable=True)
    suites_faibles_count = db.Column(db.Integer, nullable=True)
    score_risque_port = db.Column(db.Float, nullable=True)
    details_bruts = db.Column(db.Text, nullable=True)

class ComparaisonScan(db.Model):
    """Résultat de comparaison entre 2 scans"""
    __tablename__ = 'comparaison_scan'
    id = db.Column(db.Integer, primary_key=True)
    scan_ancien_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    scan_nouveau_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    cibleId = db.Column(db.Integer, db.ForeignKey('cible.id'), nullable=False)
    
    score_ia_ancien = db.Column(db.Float, nullable=True)
    score_ia_nouveau = db.Column(db.Float, nullable=True)
    evolution_ia = db.Column(db.Float, nullable=True)
    
    observation_ia = db.Column(db.Text, nullable=True)
    
    nb_corrigees = db.Column(db.Integer, default=0)
    nb_nouvelles = db.Column(db.Integer, default=0)
    nb_inchangees = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ComparaisonVulnerabilite(db.Model):
    """Chaque vulnérabilité dans la comparaison (fixed/new/unchanged)"""
    __tablename__ = 'comparaison_vulnerabilite'
    id = db.Column(db.Integer, primary_key=True)
    comparaison_id = db.Column(db.Integer, db.ForeignKey('comparaison_scan.id'), nullable=False)
    
    nom = db.Column(db.String(200), nullable=False)
    cve = db.Column(db.String(50), nullable=True)
    cvss = db.Column(db.Float, nullable=True)
    score_ia_ancien = db.Column(db.Float, nullable=True)
    score_ia_nouveau = db.Column(db.Float, nullable=True)
    
    # Classification (codes ASCII) : 'FIXED', 'NEW', 'UNCHANGED', 'AGGRAVE', 'AMELIORE'
    type = db.Column(db.String(20), nullable=False)

    details = db.Column(db.Text, nullable=True)


class ComparaisonScanMultiPort(db.Model):
    """Comparaison de deux scans MULTI-PORT (diff par (port, finding))."""
    __tablename__ = 'comparaison_scan_multiport'
    id = db.Column(db.Integer, primary_key=True)
    scan_ancien_id = db.Column(db.Integer, db.ForeignKey('scan_multiport.id'), nullable=False)
    scan_nouveau_id = db.Column(db.Integer, db.ForeignKey('scan_multiport.id'), nullable=False)
    cible_id = db.Column(db.Integer, db.ForeignKey('cible_multiport.id'), nullable=True)

    score_ia_ancien = db.Column(db.Float, nullable=True)
    score_ia_nouveau = db.Column(db.Float, nullable=True)
    evolution_ia = db.Column(db.Float, nullable=True)
    observation_ia = db.Column(db.Text, nullable=True)

    nb_corrigees = db.Column(db.Integer, default=0)
    nb_nouvelles = db.Column(db.Integer, default=0)
    nb_inchangees = db.Column(db.Integer, default=0)
    nb_aggravees = db.Column(db.Integer, default=0)
    nb_ameliorees = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ComparaisonFindingMultiPort(db.Model):
    """Chaque finding diffé, identité = (port, nom)."""
    __tablename__ = 'comparaison_finding_multiport'
    id = db.Column(db.Integer, primary_key=True)
    comparaison_id = db.Column(db.Integer, db.ForeignKey('comparaison_scan_multiport.id'), nullable=False)

    port = db.Column(db.Integer, nullable=True)
    nom = db.Column(db.String(200), nullable=False)
    cve = db.Column(db.String(50), nullable=True)
    score_ia_ancien = db.Column(db.Float, nullable=True)
    score_ia_nouveau = db.Column(db.Float, nullable=True)
    type = db.Column(db.String(20), nullable=False)   # FIXED/NEW/UNCHANGED/AGGRAVE/AMELIORE (ASCII)
    details = db.Column(db.Text, nullable=True)