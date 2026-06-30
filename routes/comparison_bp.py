from flask import Blueprint, request, jsonify, session, render_template, redirect, current_app, Response
from models.models import db
from models.models import Cible, Scan, ResultatScan
from models.models import ComparaisonScan, ComparaisonVulnerabilite
from routes.sse_util import flux_evenements, sse_event
from agent_ia.agent import vulns_scorees_locales
from agent_ia.classification import est_informatif
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
        url = 'http://' + url
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

    # Scans multi-port terminés (onglet « comparaison multi-port »).
    from agent_ia.scanner_multiport import nettoyer_cible
    from models.models import ScanMultiPort, CibleMultiPort, ResultatScanMultiPort
    scans_mp = []
    for s in ScanMultiPort.query.filter_by(statut='TERMINE').order_by(ScanMultiPort.started_at.desc()).all():
        c = CibleMultiPort.query.get(s.cible_id)
        nom = c.nom if c and c.nom else 'Inconnu'
        # Ensemble des ports réellement scannés (toutes les lignes persistées) : sert à ne
        # proposer en comparaison que des scans portant sur exactement les mêmes ports.
        ports = sorted({r.port for r in ResultatScanMultiPort.query.filter_by(scan_id=s.id).all()})
        scans_mp.append({
            'id': s.id, 'cible': nom, 'cible_normale': nettoyer_cible(nom),
            'date': s.started_at.strftime('%d/%m/%Y %H:%M') if s.started_at else 'N/A',
            'ports': ports,
        })

    return render_template('comparison_scans.html', admin=admin,
                           scans=scans_pour_template, scans_mp=scans_mp)


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
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401
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
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401
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
    def _cnt(t):
        return sum(1 for v in vulnerabilites if v.type == t)
    return {
        'comparaison_id': comparaison.id,
        'cible': cible_nom,
        'scan_ancien_id': comparaison.scan_ancien_id,
        'scan_nouveau_id': comparaison.scan_nouveau_id,
        'score_ia_ancien': comparaison.score_ia_ancien or 0,
        'score_ia_nouveau': comparaison.score_ia_nouveau or 0,
        'evolution_ia': comparaison.evolution_ia or 0,
        'observation_ia': comparaison.observation_ia,
        'nb_corrigees': _cnt('FIXED'),
        'nb_nouvelles': _cnt('NEW'),
        'nb_inchangees': _cnt('UNCHANGED'),
        'nb_aggravees': _cnt('AGGRAVE'),
        'nb_ameliorees': _cnt('AMELIORE'),
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
    nb_aggravees = 0
    nb_ameliorees = 0

    # Score IA global d'un scan = moyenne des criticités de ses vulnérabilités
    # (même logique de moyenne que le scan multi-port ; 0 si aucune vulnérabilité).
    # Calculé depuis les vulns extraites -> fonctionne pour TOUS les scans existants,
    # sans colonne BDD ni migration. (Le modèle Scan ne stocke aucun score global.)
    def _score_global(vulns):
        # Les findings informationnels (sans CVE) ne pèsent pas sur le score global.
        scores = [float(v.get('score_ia', 0) or 0) for v in vulns if not est_informatif(v)]
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

            # 5 états : informationnel toujours UNCHANGED ; sinon comparaison stricte des scores.
            if est_informatif(vuln_old):
                etat = 'UNCHANGED'
            elif score_new > score_old:
                etat = 'AGGRAVE'
            elif score_new < score_old:
                etat = 'AMELIORE'
            else:
                etat = 'UNCHANGED'

            ligne = {
                'nom': nom,
                'cve': vuln_old.get('cve'),
                'cvss': vuln_old.get('cvss'),
                'score_ia_ancien': score_old,
                'score_ia_nouveau': score_new,
                'type': etat,
                'details': f'{nom} : {etat.lower()}'
            }
            resultats.append(ligne)
            if etat == 'AGGRAVE':
                nb_aggravees += 1
            elif etat == 'AMELIORE':
                nb_ameliorees += 1
            else:
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
        f"{nb_corrigees} corrigée(s), {nb_nouvelles} nouvelle(s), "
        f"{nb_aggravees} aggravée(s), {nb_ameliorees} améliorée(s), "
        f"{nb_inchangees} inchangée(s)."
    )

    return {
        'score_ia_ancien': round(float(score_ia_ancien), 2),
        'score_ia_nouveau': round(float(score_ia_nouveau), 2),
        'evolution_ia': evolution,
        'observation_ia': observation_ia,
        'nb_corrigees': nb_corrigees,
        'nb_nouvelles': nb_nouvelles,
        'nb_inchangees': nb_inchangees,
        'nb_aggravees': nb_aggravees,
        'nb_ameliorees': nb_ameliorees,
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


# ════════════════════════════════════════════════════════════════════════════
# Comparaison MULTI-PORT (2ᵉ type) — diff par (port, nom), 5 états, scores persistés.
# ════════════════════════════════════════════════════════════════════════════
from models.models import ScanMultiPort, CibleMultiPort, ResultatScanMultiPort
from models.models import ComparaisonScanMultiPort, ComparaisonFindingMultiPort

comparaisons_mp_en_cours = {}


def _cible_mp_canonical(scan_mp):
    from agent_ia.scanner_multiport import nettoyer_cible
    c = CibleMultiPort.query.get(scan_mp.cible_id)
    return nettoyer_cible(c.nom) if c and c.nom else ''


def extraire_vulns_multiport(scan_id):
    """{(port, nom): finding} depuis details_bruts (findings DÉJÀ scorés, clé criticite)."""
    out = {}
    for r in ResultatScanMultiPort.query.filter_by(scan_id=scan_id).all():
        try:
            details = json.loads(r.details_bruts) if r.details_bruts else {}
        except Exception:
            details = {}
        for f in details.get('findings', []) or []:
            out[(r.port, f.get('nom'))] = {
                'port': r.port, 'nom': f.get('nom'), 'cve': f.get('cve'),
                'criticite': f.get('criticite', 0), 'severite': f.get('severite'),
            }
    return out


def calculer_diff_multiport(aid, nid, emit=None):
    def _emit(ev):
        if emit:
            emit(ev)
    _emit({'type': 'phase', 'message': 'Lecture des deux scans multi-port…', 'progression': 20})
    anc, nouv = extraire_vulns_multiport(aid), extraire_vulns_multiport(nid)
    cles = set(anc) | set(nouv)                       # union des (port, nom)

    def _score(vulns):
        vals = [float(v['criticite'] or 0) for v in vulns.values() if not est_informatif(v)]
        return round(sum(vals) / len(vals), 2) if vals else 0.0

    lignes, cnt = [], {'FIXED': 0, 'NEW': 0, 'UNCHANGED': 0, 'AGGRAVE': 0, 'AMELIORE': 0}
    for (port, nom) in sorted(cles, key=lambda k: (k[0] or 0, k[1] or '')):
        a, n = anc.get((port, nom)), nouv.get((port, nom))
        if a and not n:
            etat = 'FIXED'
        elif n and not a:
            etat = 'NEW'
        elif est_informatif(a):
            etat = 'UNCHANGED'                         # informationnel : jamais aggravé/amélioré
        else:
            so, sn = float(a['criticite'] or 0), float(n['criticite'] or 0)
            etat = 'AGGRAVE' if sn > so else 'AMELIORE' if sn < so else 'UNCHANGED'
        cnt[etat] += 1
        ref = a or n
        lignes.append({'port': port, 'nom': nom, 'cve': ref.get('cve'),
                       'score_ia_ancien': float(a['criticite']) if a else 0.0,
                       'score_ia_nouveau': float(n['criticite']) if n else 0.0,
                       'type': etat, 'details': f'port {port} · {nom} · {etat.lower()}'})
        _emit({'type': 'finding', 'item': lignes[-1], 'progression': 70})

    sa, sn = _score(anc), _score(nouv)
    evo = round(sn - sa, 2)
    tend = 'amélioration' if evo < 0 else 'dégradation' if evo > 0 else 'stabilité'
    obs = (f"Score multi-port : {sa:.2f} → {sn:.2f} ({tend} {abs(evo):.2f}). "
           f"{cnt['FIXED']} corrigée(s), {cnt['NEW']} nouvelle(s), {cnt['AGGRAVE']} aggravée(s), "
           f"{cnt['AMELIORE']} améliorée(s), {cnt['UNCHANGED']} inchangée(s).")
    return {'score_ia_ancien': sa, 'score_ia_nouveau': sn, 'evolution_ia': evo,
            'observation_ia': obs, 'compteurs': cnt, 'findings': lignes}


def _serialiser_comparaison_mp(cid):
    comp = ComparaisonScanMultiPort.query.get(cid)
    if not comp:
        return None
    cible = CibleMultiPort.query.get(comp.cible_id)
    rows = ComparaisonFindingMultiPort.query.filter_by(comparaison_id=cid).all()
    return {
        'comparaison_id': comp.id,
        'cible': cible.nom if cible else 'Inconnu',
        'score_ia_ancien': comp.score_ia_ancien or 0,
        'score_ia_nouveau': comp.score_ia_nouveau or 0,
        'evolution_ia': comp.evolution_ia or 0,
        'observation_ia': comp.observation_ia,
        'nb_corrigees': comp.nb_corrigees or 0, 'nb_nouvelles': comp.nb_nouvelles or 0,
        'nb_inchangees': comp.nb_inchangees or 0, 'nb_aggravees': comp.nb_aggravees or 0,
        'nb_ameliorees': comp.nb_ameliorees or 0,
        'findings': [{'port': r.port, 'nom': r.nom, 'cve': r.cve,
                      'score_ia_ancien': r.score_ia_ancien or 0,
                      'score_ia_nouveau': r.score_ia_nouveau or 0, 'type': r.type} for r in rows]
    }


@comparison_bp.route('/comparaison_multiport', methods=['POST'])
def lancer_comparaison_multiport():
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401
    data = request.get_json() or {}
    aid, nid = data.get('scan_ancien_id'), data.get('scan_nouveau_id')
    if not aid or not nid:
        return jsonify({'erreur': 'Les 2 scans sont requis'}), 400
    if str(aid) == str(nid):
        return jsonify({'erreur': 'Les scans doivent être différents'}), 400
    sa, sn = ScanMultiPort.query.get(aid), ScanMultiPort.query.get(nid)
    if not sa or not sn:
        return jsonify({'erreur': 'Scan non trouvé'}), 404
    if sa.statut != 'TERMINE' or sn.statut != 'TERMINE':
        return jsonify({'erreur': 'Les 2 scans doivent être terminés'}), 400
    if _cible_mp_canonical(sa) != _cible_mp_canonical(sn):
        return jsonify({'erreur': 'Les 2 scans doivent être de la même cible'}), 400

    comp = ComparaisonScanMultiPort(scan_ancien_id=sa.id, scan_nouveau_id=sn.id, cible_id=sa.cible_id)
    db.session.add(comp)
    db.session.commit()
    cid = comp.id
    etat = {'statut': 'EN_COURS', 'progression': 0, 'evenements': []}
    comparaisons_mp_en_cours[cid] = etat

    def emettre(ev):
        etat['evenements'].append(ev)
        if 'progression' in ev:
            etat['progression'] = ev['progression']

    app = current_app._get_current_object()
    a2, n2 = sa.id, sn.id

    def worker():
        with app.app_context():
            try:
                res = calculer_diff_multiport(a2, n2, emit=emettre)
                c = ComparaisonScanMultiPort.query.get(cid)
                c.score_ia_ancien = res['score_ia_ancien']
                c.score_ia_nouveau = res['score_ia_nouveau']
                c.evolution_ia = res['evolution_ia']
                c.observation_ia = res['observation_ia']
                cc = res['compteurs']
                c.nb_corrigees, c.nb_nouvelles, c.nb_inchangees = cc['FIXED'], cc['NEW'], cc['UNCHANGED']
                c.nb_aggravees, c.nb_ameliorees = cc['AGGRAVE'], cc['AMELIORE']
                for f in res['findings']:
                    db.session.add(ComparaisonFindingMultiPort(
                        comparaison_id=cid, port=f['port'], nom=f['nom'], cve=f.get('cve'),
                        score_ia_ancien=f['score_ia_ancien'], score_ia_nouveau=f['score_ia_nouveau'],
                        type=f['type'], details=f['details']))
                db.session.commit()
                etat['statut'] = 'TERMINE'
                etat['progression'] = 100
                emettre({'type': 'done', 'resultat': _serialiser_comparaison_mp(cid)})
            except Exception as e:
                db.session.rollback()
                etat['statut'] = 'ERREUR'
                etat['erreur'] = str(e)
                etat['evenements'].append({'type': 'error', 'message': str(e)})

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'succes': True, 'comparaison_id': cid, 'statut': 'EN_COURS'})


@comparison_bp.route('/comparaison_multiport_stream/<int:cid>')
def comparaison_mp_stream(cid):
    if 'admin_id' not in session:
        return jsonify({'erreur': 'Non authentifié'}), 401
    if cid not in comparaisons_mp_en_cours:
        comp = ComparaisonScanMultiPort.query.get(cid)
        ev = ({'type': 'done', 'resultat': _serialiser_comparaison_mp(cid)}
              if comp else {'type': 'error', 'message': 'Comparaison introuvable'})
        return Response(sse_event(ev), mimetype='text/event-stream', headers={'Cache-Control': 'no-cache'})
    return flux_evenements(lambda: comparaisons_mp_en_cours.get(cid))


@comparison_bp.route('/comparaison_multiport_resultats/<int:cid>')
def comparaison_mp_resultats(cid):
    data = _serialiser_comparaison_mp(cid)
    if data is None:
        return jsonify({'erreur': 'Comparaison non trouvée'}), 404
    return jsonify(data)