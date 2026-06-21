from flask import Blueprint, request, jsonify, session, current_app, Response
from models.models import db, Scan, ResultatScan, Vulnerabilite, Cible
from agent_ia.scanner import scanner_cible
from agent_ia.agent import analyser_resultats
from routes.sse_util import flux_evenements, sse_event
from datetime import datetime
import json
import threading


scan_bp = Blueprint('scan', __name__)


# Stockage des scans en cours
scans_en_cours = {}


@scan_bp.route('/lancer_scan', methods=['POST'])
def lancer_scan():
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401

    data = request.get_json()
    cible_url = data.get('cible')

    if not cible_url:
        return jsonify({'erreur': 'Cible manquante'}), 400

    # Créer la cible et le scan en BDD
    cible = Cible(url=cible_url, dateAjout=datetime.now())
    db.session.add(cible)
    db.session.commit()

    scan = Scan(
        cibleId=cible.id,
        adminId=session['admin_id'],
        dateDebut=datetime.now(),
        statut='EN_COURS'
    )
    db.session.add(scan)
    db.session.commit()

    scan_id = scan.id

    # Capturer le contexte applicatif avant le thread
    app = current_app._get_current_object()

    # État partagé + journal d'évènements diffusé en SSE
    etat = {'statut': 'EN_COURS', 'evenements': []}
    scans_en_cours[scan_id] = etat

    def emettre(ev):
        etat['evenements'].append(ev)

    # Lancer le scan en arrière-plan
    def executer_scan():
        with app.app_context():
            try:
                emettre({'type': 'phase', 'message': 'Connexion à la cible…', 'progression': 10})

                # 1 — SSLyze scan
                resultats_bruts = scanner_cible(cible_url)
                emettre({'type': 'phase', 'message': 'Analyse des protocoles SSL/TLS…', 'progression': 45})

                # 2 — Enregistrer résultat brut
                resultat = ResultatScan(
                    scanId=scan_id,
                    donneesSSL=json.dumps(resultats_bruts),
                    dateAnalyse=datetime.now()
                )
                db.session.add(resultat)
                db.session.commit()

                # 3 — Agent IA : chaque vulnérabilité est streamée dès qu'elle est scorée
                emettre({'type': 'phase', 'message': 'Enrichissement CVE/EPSS et scoring IA…', 'progression': 65})

                def on_finding(v):
                    emettre({'type': 'finding', 'item': {
                        'nom': v['nom'], 'cve': v['cve'], 'type': v['type'],
                        'severite': v['severite'], 'criticite': v['criticite'],
                        'source': v.get('source', 'statique')
                    }})

                vulnerabilites = analyser_resultats(resultats_bruts, on_finding=on_finding)

                # 4 — Enregistrer vulnérabilités
                vulns_enregistrees = []
                for v in vulnerabilites:
                    vuln = Vulnerabilite(
                        nom=v['nom'],
                        description=v['description'],
                        type=v['type'],
                        severite=v['severite'],
                        cve=v['cve'],
                        cvss=v['cvss'],
                        epss=v['epss'],
                        criticite=v['criticite']
                    )
                    db.session.add(vuln)
                    vulns_enregistrees.append(v)

                # 5 — Finaliser scan
                scan_obj = Scan.query.get(scan_id)
                scan_obj.dateFin = datetime.now()
                scan_obj.statut = 'TERMINE'
                db.session.commit()

                # 6 — Score TLS global
                nb_critical = sum(1 for v in vulns_enregistrees if v['severite'] == 'CRITICAL')
                nb_high = sum(1 for v in vulns_enregistrees if v['severite'] == 'HIGH')
                nb_medium = sum(1 for v in vulns_enregistrees if v['severite'] == 'MEDIUM')

                if nb_critical > 0:
                    score_tls = 'F'
                elif nb_high > 0:
                    score_tls = 'C'
                elif nb_medium > 0:
                    score_tls = 'B'
                else:
                    score_tls = 'A'

                # 7 — Expiration certificat
                expiration = resultats_bruts.get('certificat', {}).get('expire', None)

                if expiration:
                    try:
                        exp_date = datetime.fromisoformat(expiration)
                        exp_str = exp_date.strftime('%d/%m/%Y')
                        # Vérifier si expiré
                        if exp_date < datetime.now(exp_date.tzinfo):
                            exp_str = exp_str + ' ⚠️ EXPIRÉ'
                    except Exception:
                        exp_str = expiration
                else:
                    exp_str = 'N/A'

                # 8 — Stocker résultat + évènement terminal
                etat['vulnerabilites'] = vulns_enregistrees
                etat['score_tls'] = score_tls
                etat['expiration'] = exp_str
                etat['statut'] = 'TERMINE'
                emettre({'type': 'done', 'resultat': {
                    'vulnerabilites': vulns_enregistrees,
                    'score_tls': score_tls,
                    'expiration': exp_str
                }})

            except Exception as e:
                etat['statut'] = 'ERREUR'
                etat['erreur'] = str(e)
                emettre({'type': 'error', 'message': str(e)})
                import traceback
                traceback.print_exc()

    # Lancer dans un thread
    thread = threading.Thread(target=executer_scan)
    thread.daemon = True
    thread.start()

    # Retourner immédiatement
    return jsonify({
        'succes': True,
        'scan_id': scan_id,
        'statut': 'EN_COURS'
    })


@scan_bp.route('/scan_status/<int:scan_id>')
def scan_status(scan_id):
    """État du scan (sans le journal d'évènements). Conservé pour compatibilité ;
    le front utilise désormais /scan_stream (SSE). N'efface plus la mémoire afin de
    permettre la reconnexion après un rechargement."""
    if scan_id not in scans_en_cours:
        return jsonify({'statut': 'INCONNU'})
    etat = scans_en_cours[scan_id]
    return jsonify({k: v for k, v in etat.items() if k != 'evenements'})


@scan_bp.route('/scan_stream/<int:scan_id>')
def scan_stream(scan_id):
    """Flux SSE du scan : phases, findings temps réel, puis 'done'/'error'."""
    if scan_id not in scans_en_cours:
        scan = Scan.query.get(scan_id)
        msg = ('Résultat expiré (serveur redémarré). Relancez le scan.'
               if scan else 'Scan introuvable.')
        return Response(sse_event({'type': 'error', 'message': msg}),
                        mimetype='text/event-stream', headers={'Cache-Control': 'no-cache'})
    return flux_evenements(lambda: scans_en_cours.get(scan_id))