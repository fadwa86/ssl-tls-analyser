from flask import Blueprint, request, jsonify, session, render_template, redirect, current_app, Response
from models.models import db
from models.models import Cible, Scan, ResultatScan
from models.models import ComparaisonScan, ComparaisonVulnerabilite
from routes.sse_util import flux_evenements, sse_event
from agent_ia.agent import vulns_scorees_locales
from datetime import datetime
import threading
import json
from urllib.parse import urlparse

comparison_bp = Blueprint('comparison_bp', __name__)
comparaisons_en_cours = {}


def normaliser_url(url):
    if not url:
        return ''
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    if ':' in host:
        host = host.split(':')[0]
    path = parsed.path.rstrip('/')
    return host + path


def get_cible_canonical(scan):
    cible = Cible.query.get(scan.cibleId)
    if not cible:
        return ''
    url = cible.url if cible.url else ''
    if not url and cible.adresseIp:
        url = cible.adresseIp
    return normaliser_url(url)


@comparison_bp.route('/comparaison_scans')
def comparaison_scans_page():
    if 'admin_id' not in session:
        return redirect('/login')

    from models.models import Administrateur
    admin = Administrateur.query.get(session['admin_id'])

    scans_termines = Scan.query.filter_by(statut='TERMINE').order_by(Scan.dateDebut.desc()).all()

    scans_pour_template = []
    for scan in scans_termines:
        cible = Cible.query.get(scan.cibleId)
        url_cible = cible.url if cible and cible.url else (cible.adresseIp if cible else 'Inconnu')
        scans_pour_template.append({
            'id': scan.id,
            'cible': url_cible,
            'cible_normale': normaliser_url(url_cible),
            'dateDebut': scan.dateDebut.strftime('%d/%m/%Y %H:%M') if scan.dateDebut else 'N/A',
            'statut': scan.statut
        })

    return render_template('comparison_scans.html', admin=admin, scans=scans_pour_template)


@comparison_bp.route('/comparaison_scans', methods=['POST'])
def lancer_comparaison():
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401

    data = request.get_json() or {}
    scan_ancien_id = data.get('scan_ancien_id')
    scan_nouveau_id = data.get('scan_nouveau_id')

    if not scan_ancien_id or not scan_nouveau_id:
        return jsonify({'erreur': 'Les 2 scans sont requis'}), 400

    if str(scan_ancien_id) == str(scan_nouveau_id):
        return jsonify({'erreur': 'Les scans doivent être différents'}), 400

    scan_ancien = Scan.query.get(scan_ancien_id)
    scan_nouveau = Scan.query.get(scan_nouveau_id)

    if not scan_ancien or not scan_nouveau:
        return jsonify({'erreur': 'Scan non trouvé'}), 404

    if scan_ancien.statut != 'TERMINE' or scan_nouveau.statut != 'TERMINE':
        return jsonify({'erreur': 'Les 2 scans doivent être terminés'}), 400

    url_ancien = get_cible_canonical(scan_ancien)
    url_nouveau = get_cible_canonical(scan_nouveau)

    if not url_ancien or not url_nouveau:
        return jsonify({'erreur': 'Impossible de déterminer la cible'}), 400

    if url_ancien != url_nouveau:
        return jsonify({
            'erreur': 'Les 2 scans doivent être du même domaine',
            'cible_ancien': url_ancien,
            'cible_nouveau': url_nouveau
        }), 400

    comparaison = ComparaisonScan(
        scan_ancien_id=scan_ancien.id,
        scan_nouveau_id=scan_nouveau.id,
        cibleId=scan_ancien.cibleId
    )
    db.session.add(comparaison)
    db.session.commit()

    comparaison_id = comparaison.id
    etat = {'statut': 'EN_COURS', 'progression': 0, 'evenements': []}
    comparaisons_en_cours[comparaison_id] = etat

    def emettre(ev):
        etat['evenements'].append(ev)
        if 'progression' in ev:
            etat['progression'] = ev['progression']

    app = current_app._get_current_object()
    # IDs capturés en valeurs simples : le thread worker ne doit JAMAIS toucher les
    # objets ORM chargés dans la requête (sessions/connexions distinctes -> corruption
    # pymysql une fois la requête terminée). Il re-requête tout via sa propre session.
    aid, nid = scan_ancien.id, scan_nouveau.id

    def thread_comparaison():
        with app.app_context():
            try:
                resultats_diff = calculer_diff_scans(aid, nid, emit=emettre)

                comparaison_obj = ComparaisonScan.query.get(comparaison_id)
                comparaison_obj.score_ia_ancien = resultats_diff['score_ia_ancien']
                comparaison_obj.score_ia_nouveau = resultats_diff['score_ia_nouveau']
                comparaison_obj.evolution_ia = resultats_diff['evolution_ia']
                comparaison_obj.observation_ia = resultats_diff['observation_ia']
                comparaison_obj.nb_corrigees = resultats_diff['nb_corrigees']
                comparaison_obj.nb_nouvelles = resultats_diff['nb_nouvelles']
                comparaison_obj.nb_inchangees = resultats_diff['nb_inchangees']

                for vuln_diff in resultats_diff['vulnerabilites']:
                    vuln_db = ComparaisonVulnerabilite(
                        comparaison_id=comparaison_id,
                        nom=vuln_diff['nom'],
                        cve=vuln_diff.get('cve'),
                        cvss=vuln_diff.get('cvss'),
                        score_ia_ancien=vuln_diff.get('score_ia_ancien'),
                        score_ia_nouveau=vuln_diff.get('score_ia_nouveau'),
                        type=vuln_diff['type'],
                        details=json.dumps(vuln_diff, ensure_ascii=False)
                    )
                    db.session.add(vuln_db)

                db.session.commit()
                etat['statut'] = 'TERMINE'
                etat['progression'] = 100
                # 'done' : on embarque le détail complet pour un rendu direct côté
                # front (pas de refetch juste après la fermeture du flux SSE).
                emettre({'type': 'done', 'resultat': _serialiser_comparaison(comparaison_id)})
            except Exception as e:
                db.session.rollback()
                etat['statut'] = 'ERREUR'
                etat['erreur'] = str(e)
                etat['evenements'].append({'type': 'error', 'message': str(e)})

    threading.Thread(target=thread_comparaison, daemon=True).start()

    return jsonify({'succes': True, 'comparaison_id': comparaison_id, 'statut': 'EN_COURS'})


@comparison_bp.route('/comparaison_status/<int:comparaison_id>')
def comparaison_status(comparaison_id):
    if comparaison_id not in comparaisons_en_cours:
        comparaison = ComparaisonScan.query.get(comparaison_id)
        if not comparaison:
            return jsonify({'erreur': 'Comparaison non trouvée'}), 404
        return jsonify({
            'statut': 'TERMINE',
            'progression': 100,
            'score_ia_ancien': comparaison.score_ia_ancien,
            'score_ia_nouveau': comparaison.score_ia_nouveau,
            'evolution_ia': comparaison.evolution_ia
        })
    etat = comparaisons_en_cours[comparaison_id]
    return jsonify({k: v for k, v in etat.items() if k != 'evenements'})


@comparison_bp.route('/comparaison_stream/<int:comparaison_id>')
def comparaison_stream(comparaison_id):
    """Flux SSE de la comparaison : chaque partie (extraction, corrigées, nouvelles,
    inchangées, score) est diffusée dès qu'elle est calculée."""
    if comparaison_id not in comparaisons_en_cours:
        comparaison = ComparaisonScan.query.get(comparaison_id)
        ev = ({'type': 'done', 'resultat': _serialiser_comparaison(comparaison_id)}
              if comparaison else {'type': 'error', 'message': 'Comparaison introuvable'})
        return Response(sse_event(ev), mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache'})
    return flux_evenements(lambda: comparaisons_en_cours.get(comparaison_id))


def _serialiser_comparaison(comparaison_id):
    """Détail complet d'une comparaison depuis la BDD (None si absente). Source unique
    pour l'endpoint _resultats ET l'évènement SSE 'done' (rendu direct côté front)."""
    comparaison = ComparaisonScan.query.get(comparaison_id)
    if not comparaison:
        return None
    cible = Cible.query.get(comparaison.cibleId)
    cible_nom = cible.url if cible and cible.url else (cible.adresseIp if cible else 'Inconnu')
    vulnerabilites = ComparaisonVulnerabilite.query.filter_by(comparaison_id=comparaison_id).all()
    return {
        'comparaison_id': comparaison.id,
        'cible': cible_nom,
        'scan_ancien_id': comparaison.scan_ancien_id,
        'scan_nouveau_id': comparaison.scan_nouveau_id,
        'score_ia_ancien': comparaison.score_ia_ancien or 0,
        'score_ia_nouveau': comparaison.score_ia_nouveau or 0,
        'evolution_ia': comparaison.evolution_ia or 0,
        'observation_ia': comparaison.observation_ia,
        'nb_corrigees': comparaison.nb_corrigees or 0,
        'nb_nouvelles': comparaison.nb_nouvelles or 0,
        'nb_inchangees': comparaison.nb_inchangees or 0,
        'vulnerabilites': [{
            'nom': v.nom,
            'cve': v.cve,
            'cvss': v.cvss,
            'score_ia_ancien': v.score_ia_ancien or 0,
            'score_ia_nouveau': v.score_ia_nouveau or 0,
            'type': v.type,
            'details': v.details
        } for v in vulnerabilites]
    }


@comparison_bp.route('/comparaison_resultats/<int:comparaison_id>')
def comparaison_resultats(comparaison_id):
    try:
        data = _serialiser_comparaison(comparaison_id)
        if data is None:
            return jsonify({'erreur': 'Comparaison non trouvée'}), 404
        return jsonify(data)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


def calculer_diff_scans(scan_ancien_id, scan_nouveau_id, emit=None):
    """Diffe deux scans. `emit(ev)` (optionnel) diffuse chaque partie en SSE."""
    def _emit(ev):
        if emit:
            emit(ev)

    _emit({'type': 'phase', 'message': 'Lecture de l’ancien scan…', 'progression': 15})
    resultats_ancien = ResultatScan.query.filter_by(scanId=scan_ancien_id).all()
    resultats_nouveau = ResultatScan.query.filter_by(scanId=scan_nouveau_id).all()

    vulns_ancien = extraire_vulnerabilites_depuis_resultats(resultats_ancien)
    vulns_nouveau = extraire_vulnerabilites_depuis_resultats(resultats_nouveau)
    _emit({'type': 'phase',
           'message': f'{len(vulns_ancien)} vs {len(vulns_nouveau)} vulnérabilités — comparaison…',
           'progression': 35})

    ancien_dict = {v['nom']: v for v in vulns_ancien}
    nouveau_dict = {v['nom']: v for v in vulns_nouveau}

    resultats = []
    nb_corrigees = 0
    nb_nouvelles = 0
    nb_inchangees = 0

    # Score IA global d'un scan = moyenne des criticités de ses vulnérabilités
    # (même logique de moyenne que le scan multi-port ; 0 si aucune vulnérabilité).
    # Calculé depuis les vulns extraites -> fonctionne pour TOUS les scans existants,
    # sans colonne BDD ni migration. (Le modèle Scan ne stocke aucun score global.)
    def _score_global(vulns):
        scores = [float(v.get('score_ia', 0) or 0) for v in vulns]
        return round(sum(scores) / len(scores), 2) if scores else 0.0

    score_ia_ancien = _score_global(vulns_ancien)
    score_ia_nouveau = _score_global(vulns_nouveau)

    for nom, vuln in ancien_dict.items():
        if nom not in nouveau_dict:
            ligne = {
                'nom': nom,
                'cve': vuln.get('cve'),
                'cvss': vuln.get('cvss'),
                'score_ia_ancien': vuln.get('score_ia', 0),
                'score_ia_nouveau': 0.0,
                'type': 'FIXED',
                'details': f'{nom} a été corrigée'
            }
            resultats.append(ligne)
            nb_corrigees += 1
            _emit({'type': 'finding', 'item': ligne, 'progression': 55})

    for nom, vuln in nouveau_dict.items():
        if nom not in ancien_dict:
            ligne = {
                'nom': nom,
                'cve': vuln.get('cve'),
                'cvss': vuln.get('cvss'),
                'score_ia_ancien': 0.0,
                'score_ia_nouveau': vuln.get('score_ia', 0),
                'type': 'NEW',
                'details': f'{nom} est une nouvelle vulnérabilité'
            }
            resultats.append(ligne)
            nb_nouvelles += 1
            _emit({'type': 'finding', 'item': ligne, 'progression': 70})

    for nom, vuln_old in ancien_dict.items():
        if nom in nouveau_dict:
            vuln_new = nouveau_dict[nom]
            score_old = float(vuln_old.get('score_ia', 0) or 0)
            score_new = float(vuln_new.get('score_ia', 0) or 0)

            ligne = {
                'nom': nom,
                'cve': vuln_old.get('cve'),
                'cvss': vuln_old.get('cvss'),
                'score_ia_ancien': score_old,
                'score_ia_nouveau': score_new,
                'type': 'UNCHANGED',
                'details': f'{nom} inchangé'
            }
            resultats.append(ligne)
            nb_inchangees += 1
            _emit({'type': 'finding', 'item': ligne, 'progression': 85})

    _emit({'type': 'phase', 'message': 'Calcul du score IA et de l’observation…', 'progression': 95})
    evolution = round(float(score_ia_nouveau) - float(score_ia_ancien), 2)

    if evolution < 0:
        tendance = "amélioration"
    elif evolution > 0:
        tendance = "dégradation"
    else:
        tendance = "stabilité"

    observation_ia = (
        f"Le score IA global passe de {float(score_ia_ancien):.2f} à {float(score_ia_nouveau):.2f}. "
        f"Il s'agit d'une {tendance} de {abs(evolution):.2f}. "
        f"{nb_corrigees} vulnérabilités ont été corrigées, "
        f"{nb_nouvelles} nouvelles vulnérabilités sont apparues, "
        f"et {nb_inchangees} sont restées inchangées."
    )

    return {
        'score_ia_ancien': round(float(score_ia_ancien), 2),
        'score_ia_nouveau': round(float(score_ia_nouveau), 2),
        'evolution_ia': evolution,
        'observation_ia': observation_ia,
        'nb_corrigees': nb_corrigees,
        'nb_nouvelles': nb_nouvelles,
        'nb_inchangees': nb_inchangees,
        'vulnerabilites': resultats
    }


def extraire_vulnerabilites_depuis_resultats(resultats_scan):
    vulns = []
    for r in resultats_scan:
        try:
            raw = r.donneesSSL
            if not raw:
                continue
            data = json.loads(raw) if isinstance(raw, str) else raw

            if isinstance(data, dict):
                if 'protocoles' in data or 'heartbleed' in data or 'robot' in data:
                    # Sortie brute SSLyze : on dérive les vulnérabilités via le mapping
                    # partagé du scan (cohérence garantie, scoring RF local, sans réseau).
                    for v in vulns_scorees_locales(data):
                        vulns.append({
                            'nom': v['nom'],
                            'cve': v.get('cve'),
                            'cvss': v.get('cvss'),
                            'score_ia': v.get('score_ia', 0)
                        })
                elif 'vulnerabilites' in data and isinstance(data['vulnerabilites'], list):
                    for v in data['vulnerabilites']:
                        if isinstance(v, dict):
                            vulns.append({
                                'nom': v.get('nom') or v.get('name') or 'Inconnue',
                                'cve': v.get('cve'),
                                'cvss': v.get('cvss'),
                                'score_ia': v.get('score_ia') or v.get('score') or 0
                            })
                else:
                    nom = data.get('nom') or data.get('name')
                    if nom:
                        vulns.append({
                            'nom': nom,
                            'cve': data.get('cve'),
                            'cvss': data.get('cvss'),
                            'score_ia': data.get('score_ia') or data.get('score') or 0
                        })

            elif isinstance(data, list):
                for v in data:
                    if isinstance(v, dict):
                        vulns.append({
                            'nom': v.get('nom') or v.get('name') or 'Inconnue',
                            'cve': v.get('cve'),
                            'cvss': v.get('cvss'),
                            'score_ia': v.get('score_ia') or v.get('score') or 0
                        })
        except Exception:
            continue
    return vulns