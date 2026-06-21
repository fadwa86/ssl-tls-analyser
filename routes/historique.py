from flask import Blueprint, render_template, session, redirect, url_for
from models.models import db, Scan, Cible, ResultatScan, Administrateur
from models.models import ScanMultiPort, CibleMultiPort, ResultatScanMultiPort
from agent_ia.agent import analyser_resultats
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
                protocoles = donnees.get('protocoles', {})
                if protocoles.get('ssl2'): nb_vulns += 1
                if protocoles.get('ssl3'): nb_vulns += 1
                if protocoles.get('tls10'): nb_vulns += 1
                if protocoles.get('tls11'): nb_vulns += 1
                if donnees.get('heartbleed'): nb_vulns += 1
                if donnees.get('robot'): nb_vulns += 1
            except: pass

        scan.cible_url = cible.url
        scan.nb_vulns = nb_vulns
        scans_data.append(scan)

    # Scans multi-port (modèle séparé). Résumé : nb de ports analysés + total findings.
    scans_mp = []
    for s in ScanMultiPort.query.order_by(ScanMultiPort.started_at.desc()).all():
        cible_mp = CibleMultiPort.query.get(s.cible_id)
        resultats = ResultatScanMultiPort.query.filter_by(scan_id=s.id).all()
        # On ne compte que les ports TLS réels (on ignore les ports fermés/non-TLS).
        nb_ports_tls = 0
        nb_findings = 0
        for r in resultats:
            try:
                details = json.loads(r.details_bruts) if r.details_bruts else {}
            except Exception:
                details = {}
            if details.get('statut') == 'ERREUR':
                continue
            nb_ports_tls += 1
            nb_findings += len(details.get('findings', []))
        scans_mp.append({
            'id': s.id,
            'cible': cible_mp.nom if cible_mp else 'Inconnu',
            'date': s.started_at,
            'statut': s.statut,
            'score': s.score_risque_global,
            'nb_ports': nb_ports_tls,
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

    ports = []
    for r in resultats:
        try:
            details = json.loads(r.details_bruts) if r.details_bruts else {}
        except Exception:
            details = {}
        if details.get('statut') == 'ERREUR':
            continue   # port fermé / non-TLS : masqué (comme dans la vue de scan)
        ports.append({
            'port': r.port,
            'protocole': r.protocole,
            'starttls': r.starttls_utilise,
            'tls': r.tls_preferé,
            'cn': r.certificat_cn,
            'expire': r.certificat_expire,
            'findings': [f.get('nom') for f in details.get('findings', [])],
            'score': r.score_risque_port,
            'statut': details.get('statut'),
        })

    return render_template('multiport_detail.html',
        scan=scan, cible=cible, ports=ports, admin=admin)
    