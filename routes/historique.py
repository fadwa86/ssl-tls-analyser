from flask import Blueprint, render_template, session, redirect, url_for
from models.models import db, Scan, Cible, ResultatScan, Administrateur
from models.models import ScanMultiPort, CibleMultiPort, ResultatScanMultiPort
from agent_ia.agent import analyser_resultats, vulns_scorees_locales
from agent_ia.classification import est_informatif
import json

historique_bp = Blueprint('historique', __name__)

@historique_bp.route('/historique')
def historique():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])

    scans = db.session.query(Scan, Cible).join(
        Cible, Scan.cibleId == Cible.id
    ).filter(Scan.adminId == session['admin_id']).order_by(Scan.dateDebut.desc()).all()

    scans_data = []
    for scan, cible in scans:
        resultat = ResultatScan.query.filter_by(scanId=scan.id).first()
        nb_vulns = 0
        if resultat and resultat.donneesSSL:
            try:
                donnees = json.loads(resultat.donneesSSL)
                # Compte TOUTES les vraies vulns (protocoles + ciphers + certificat),
                # informationnels exclus — cohérent avec le détail et le multi-port.
                # vulns_scorees_locales = scoring RF local, SANS appel réseau NVD/FIRST.
                nb_vulns = sum(1 for f in vulns_scorees_locales(donnees) if not est_informatif(f))
            except Exception: pass

        scan.cible_url = cible.url
        scan.nb_vulns = nb_vulns
        scans_data.append(scan)

    # Scans multi-port : on classe les ports en 3 catégories (TLS-OK / échec-TLS / non-TLS).
    # nb_findings ne compte que les VRAIES vulns (informationnels exclus).
    scans_mp = []
    for s in ScanMultiPort.query.order_by(ScanMultiPort.started_at.desc()).all():
        cible_mp = CibleMultiPort.query.get(s.cible_id)
        resultats = ResultatScanMultiPort.query.filter_by(scan_id=s.id).all()
        nb_tls = nb_ferme = nb_nontls = nb_findings = 0
        for r in resultats:
            try:
                details = json.loads(r.details_bruts) if r.details_bruts else {}
            except Exception:
                details = {}
            statut = details.get('statut') or 'SUCCES'   # vieux scans sans statut -> TLS-OK
            ouvert = details.get('ouvert', True)         # vieux scans -> supposés ouverts
            if statut == 'SUCCES':
                nb_tls += 1
                nb_findings += sum(1 for f in details.get('findings', []) if not est_informatif(f))
            elif ouvert:
                nb_nontls += 1          # ouvert mais sans TLS (non-TLS ou handshake échoué)
            else:
                nb_ferme += 1           # fermé / injoignable
        scans_mp.append({
            'id': s.id,
            'cible': cible_mp.nom if cible_mp else 'Inconnu',
            'date': s.started_at,
            'statut': s.statut,
            'score': s.score_risque_global,
            'nb_ports': nb_tls,
            'nb_ports_nontls': nb_nontls,
            'nb_ports_fermes': nb_ferme,
            'nb_findings': nb_findings,
        })

    return render_template('historique.html', scans=scans_data, scans_mp=scans_mp, admin=admin)
@historique_bp.route('/historique/<int:scan_id>')
def detail_scan(scan_id):
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])
    scan = Scan.query.get_or_404(scan_id)
    cible = Cible.query.get(scan.cibleId)

    resultat = ResultatScan.query.filter_by(scanId=scan_id).first()
    vulnerabilites = []

    if resultat and resultat.donneesSSL:
        try:
            donnees = json.loads(resultat.donneesSSL)
            vulnerabilites = analyser_resultats(donnees)
        except Exception as e:
            print("Erreur:", e)

    return render_template('detail_scan.html',
        scan=scan,
        cible=cible,
        vulnerabilites=vulnerabilites,
        admin=admin
    )


@historique_bp.route('/historique/multiport/<int:scan_id>')
def detail_multiport(scan_id):
    """Détail d'un scan multi-port : TOUS les ports analysés (y compris fermés)."""
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])
    scan = ScanMultiPort.query.get_or_404(scan_id)
    cible = CibleMultiPort.query.get(scan.cible_id)

    resultats = ResultatScanMultiPort.query.filter_by(scan_id=scan_id)\
        .order_by(ResultatScanMultiPort.port).all()

    # On renvoie TOUS les ports (le template les regroupe en TLS-OK / échec-TLS / non-TLS).
    ports = []
    for r in resultats:
        try:
            details = json.loads(r.details_bruts) if r.details_bruts else {}
        except Exception:
            details = {}
        ports.append({
            'port': r.port,
            'protocole': r.protocole,
            'starttls': r.starttls_utilise,
            'tls': r.tls_preferé,
            'cn': r.certificat_cn,
            'expire': r.certificat_expire,
            'findings': details.get('findings', []),       # dicts complets (nom/cve/severite…)
            'score': r.score_risque_port,
            'statut': details.get('statut') or 'SUCCES',
            'ouvert': details.get('ouvert', True),          # vieux scans -> supposés ouverts
        })

    return render_template('multiport_detail.html',
        scan=scan, cible=cible, ports=ports, admin=admin)
    