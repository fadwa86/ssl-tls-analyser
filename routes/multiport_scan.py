from flask import Blueprint, request, jsonify, session, render_template, redirect, current_app, Response
from models.models import db
from models.models import CibleMultiPort, ScanMultiPort, ResultatScanMultiPort
from agent_ia.scanner_multiport import scanner_cible_multiport
from agent_ia.agent_multiport import analyser_incoherence_multiport, calculer_score_risque_global
from routes.sse_util import flux_evenements, sse_event
from datetime import datetime, timezone
import threading
import json

multiport_bp = Blueprint('multiport_scan', __name__)
scans_multiport_en_cours = {}

@multiport_bp.route('/lancer_scan_multiport')
def lancer_scan_multiport_page():
    if 'admin_id' not in session:
        return redirect('/login')
    from models.models import Administrateur
    admin = Administrateur.query.get(session['admin_id'])
    return render_template('multiport_scan.html', admin=admin)


@multiport_bp.route('/lancer_scan_multiport', methods=['POST'])
def lancer_scan_multiport():
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401

    data = request.get_json()
    cible_nom = data.get('cible')
    mode = data.get('mode', 'auto')                      # 'auto' = découverte top-100
    ports = data.get('ports')                            # liste manuelle (mode='manuel')

    if not cible_nom:
        return jsonify({'erreur': 'Cible requise'}), 400

    cible = CibleMultiPort(nom=cible_nom)
    db.session.add(cible)
    db.session.commit()

    scan = ScanMultiPort(cible_id=cible.id, statut='EN_COURS')
    db.session.add(scan)
    db.session.commit()

    scan_id = scan.id
    scans_multiport_en_cours[scan_id] = {
        'statut': 'EN_COURS', 'progression': 0, 'resultats': [],
        'ports_ouverts': [], 'nb_ports': 1, 'evenements': []
    }

    app = current_app._get_current_object()

    def thread_scan():
        with app.app_context():
            try:
                etat = scans_multiport_en_cours[scan_id]

                def emettre(ev):
                    etat['evenements'].append(ev)

                emettre({'type': 'phase', 'message': 'Découverte des ports ouverts…', 'progression': 5})

                def callback_decouverte(ports_ouverts):
                    # Recale le dénominateur de progression sur les ports réellement ouverts.
                    etat['nb_ports'] = max(len(ports_ouverts), 1)
                    etat['ports_ouverts'] = ports_ouverts
                    emettre({'type': 'phase',
                             'message': f'{len(ports_ouverts)} port(s) ouvert(s) — analyse TLS en cours…',
                             'progression': 10})

                def callback_progress(port, resultat):
                    etat['progression'] = min(etat['progression'] + 100 / etat['nb_ports'], 100)
                    etat['resultats'].append(resultat)
                    # Ligne partielle diffusée en temps réel
                    emettre({'type': 'finding', 'item': {
                        'port': resultat.get('port'),
                        'protocole': resultat.get('protocole'),
                        'logiciel': resultat.get('logiciel', ''),
                        'tls': resultat.get('protocoles', {}).get('preferred'),
                        'cn': resultat.get('certificat', {}).get('cn'),
                        'score': resultat.get('score_risque'),
                        'statut': resultat.get('statut')
                    }, 'progression': round(etat['progression'])})

                resultats_bruts = scanner_cible_multiport(
                    cible=cible_nom, ports=ports, mode=mode,
                    progress_callback=callback_progress,
                    decouverte_callback=callback_decouverte
                )

                if 'erreur' in resultats_bruts:
                    etat['statut'] = 'ERREUR'
                    etat['erreur'] = resultats_bruts['erreur']
                    emettre({'type': 'error', 'message': resultats_bruts['erreur']})
                    return

                emettre({'type': 'phase', 'message': 'Analyse des incohérences inter-ports…', 'progression': 95})

                # Seuls les ports TLS analysés entrent dans l'analyse d'incohérence.
                resultats_tls = [r for r in resultats_bruts['resultats']
                                 if r.get('statut') != 'IGNORE']
                observation_ia, features_incoherence = analyser_incoherence_multiport(resultats_tls)
                score_global = calculer_score_risque_global(resultats_tls, features_incoherence)

                serveur = resultats_bruts.get('serveur', {})

                scan_obj = ScanMultiPort.query.get(scan_id)
                scan_obj.statut = 'TERMINE'
                scan_obj.score_risque_global = score_global
                scan_obj.observation_ia = observation_ia or 'Aucune incohérence multi-ports détectée.'
                scan_obj.completed_at = datetime.utcnow()

                for resultat_port in resultats_tls:
                    resultat_port['serveur'] = serveur   # disponible pour le PDF (pas de réseau au rendu)
                    cert = resultat_port.get('certificat', {})

                    # ✅ CORRECTION : calculer si vraiment expiré
                    cert_expiration = None
                    cert_expire = False
                    if cert.get('expire'):
                        try:
                            cert_expiration = datetime.fromisoformat(cert['expire'])
                            if cert_expiration.tzinfo is None:
                                cert_expiration = cert_expiration.replace(tzinfo=timezone.utc)
                            cert_expire = cert_expiration < datetime.now(timezone.utc)
                        except:
                            pass

                    resultat_db = ResultatScanMultiPort(
                        scan_id=scan_id,
                        port=resultat_port['port'],
                        protocole=resultat_port.get('protocole'),
                        starttls_utilise=resultat_port.get('starttls_utilise', False),
                        tls_supported=resultat_port.get('protocoles', {}).get('tls_supported_str'),
                        tls_preferé=resultat_port.get('protocoles', {}).get('preferred'),
                        certificat_expiration=cert_expiration,
                        certificat_expire=cert_expire,  # ✅ CORRIGÉ
                        certificat_valid=cert.get('valid'),
                        certificat_cn=cert.get('cn'),
                        certificat_issuer=cert.get('issuer'),
                        vuln_heartbleed=resultat_port.get('heartbleed', False),
                        vuln_robot=resultat_port.get('robot', False),
                        vuln_ccs=resultat_port.get('ccs', False),
                        vuln_ticketbleed=resultat_port.get('ticketbleed', False),
                        vuln_downgrade=resultat_port.get('downgrade', False),
                        score_risque_port=resultat_port.get('score_risque'),
                        details_bruts=json.dumps(resultat_port)
                    )
                    db.session.add(resultat_db)

                db.session.commit()

                etat['statut'] = 'TERMINE'
                etat['progression'] = 100
                etat['score_global'] = score_global
                etat['observation_ia'] = scan_obj.observation_ia
                # 'done' : on embarque le détail complet pour un rendu direct côté
                # front (pas de refetch juste après la fermeture du flux SSE).
                emettre({'type': 'done', 'resultat': _serialiser_multiport(scan_id)})

            except Exception as e:
                etat['statut'] = 'ERREUR'
                etat['erreur'] = str(e)
                etat['evenements'].append({'type': 'error', 'message': str(e)})

    threading.Thread(target=thread_scan).start()
    return jsonify({'succes': True, 'scan_id': scan_id, 'statut': 'EN_COURS', 'cible': cible_nom})


@multiport_bp.route('/scan_multiport_status/<int:scan_id>')
def scan_multiport_status(scan_id):
    if scan_id not in scans_multiport_en_cours:
        scan = ScanMultiPort.query.get(scan_id)
        if not scan:
            return jsonify({'erreur': 'Scan non trouvé'}), 404
        return jsonify({
            'statut': scan.statut,
            'progression': 100 if scan.statut == 'TERMINE' else 50,
            'score_global': scan.score_risque_global,
            'observation_ia': scan.observation_ia
        })
    etat = scans_multiport_en_cours[scan_id]
    return jsonify({k: v for k, v in etat.items() if k != 'evenements'})


@multiport_bp.route('/scan_multiport_stream/<int:scan_id>')
def scan_multiport_stream(scan_id):
    """Flux SSE du scan multi-port : phases, ports détectés en temps réel, puis 'done'."""
    if scan_id not in scans_multiport_en_cours:
        scan = ScanMultiPort.query.get(scan_id)
        if not scan:
            return Response(sse_event({'type': 'error', 'message': 'Scan introuvable'}),
                            mimetype='text/event-stream', headers={'Cache-Control': 'no-cache'})
        ev = ({'type': 'done', 'resultat': _serialiser_multiport(scan_id)}
              if scan.statut == 'TERMINE'
              else {'type': 'error', 'message': 'Résultat expiré, relancez le scan.'})
        return Response(sse_event(ev), mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache'})
    return flux_evenements(lambda: scans_multiport_en_cours.get(scan_id))


def _serialiser_multiport(scan_id):
    """Détail complet d'un scan multi-port depuis la BDD (None si absent).
    Source unique pour l'endpoint _resultats ET l'évènement SSE 'done' (le front
    rend directement depuis le payload 'done', sans refetch après le flux)."""
    scan = ScanMultiPort.query.get(scan_id)
    if not scan:
        return None
    cible = CibleMultiPort.query.get(scan.cible_id)
    cible_nom = cible.nom if cible else 'Inconnu'
    lignes = []
    for r in ResultatScanMultiPort.query.filter_by(scan_id=scan_id).all():
        details = json.loads(r.details_bruts) if r.details_bruts else {}
        lignes.append({
            'port': r.port,
            'protocole': r.protocole,
            'logiciel': details.get('logiciel', ''),
            'classe': details.get('classe', ''),
            'statut': details.get('statut'),
            'erreur': details.get('erreur'),
            'findings': [f.get('nom') for f in details.get('findings', [])],
            'starttls_utilise': r.starttls_utilise,
            'tls_supported': r.tls_supported,
            'tls_preferé': r.tls_preferé,
            'certificat_expiration': r.certificat_expiration.isoformat() if r.certificat_expiration else None,
            'certificat_expire': r.certificat_expire,
            'certificat_valid': r.certificat_valid,
            'certificat_cn': r.certificat_cn,
            'vuln_heartbleed': r.vuln_heartbleed,
            'vuln_robot': r.vuln_robot,
            'vuln_ccs': r.vuln_ccs,
            'score_risque_port': r.score_risque_port
        })
    return {
        'scan_id': scan_id,
        'cible': cible_nom,
        'statut': scan.statut,
        'score_global': scan.score_risque_global,
        'observation_ia': scan.observation_ia,
        'resultats': lignes
    }


@multiport_bp.route('/scan_multiport_resultats/<int:scan_id>')
def scan_multiport_resultats(scan_id):
    try:
        data = _serialiser_multiport(scan_id)
        if data is None:
            return jsonify({'erreur': 'Scan non trouvé'}), 404
        return jsonify(data)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500