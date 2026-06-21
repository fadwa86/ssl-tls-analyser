from agent_ia.modele_rf import predire_score
import requests
import concurrent.futures

# Cache API
_cache_api = {}


def get_nvd(cve_id, cvss_statique):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r   = requests.get(url, timeout=2, headers={'User-Agent': 'TLS-Analyser/1.0'})
        if r.status_code == 200:
            data    = r.json()
            metrics = data['vulnerabilities'][0]['cve'].get('metrics', {})
            if 'cvssMetricV31' in metrics:
                return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV30' in metrics:
                return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
    except Exception as e:
        print(f"[NVD] Erreur {cve_id} : {e}")
    return cvss_statique


def get_first(cve_id, epss_statique):
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        r   = requests.get(url, timeout=2)
        if r.status_code == 200:
            data = r.json()
            if data.get('data') and len(data['data']) > 0:
                return float(data['data'][0]['epss'])
    except Exception as e:
        print(f"[FIRST] Erreur {cve_id} : {e}")
    return epss_statique


def get_metadata_temps_reel(cve_id, cvss_statique, epss_statique):
    if cve_id in _cache_api:
        print(f"[CACHE] {cve_id}")
        return _cache_api[cve_id]

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_nvd   = executor.submit(get_nvd,   cve_id, cvss_statique)
        future_first = executor.submit(get_first,  cve_id, epss_statique)
        cvss = future_nvd.result()
        epss = future_first.result()

    source = 'temps_reel' if (cvss != cvss_statique or epss != epss_statique) else 'statique'
    print(f"[API] {cve_id} → cvss={cvss}, epss={epss}, source={source}")

    _cache_api[cve_id] = (cvss, epss, source)
    return cvss, epss, source


def determiner_severite(score):
    """
    Détermine la sévérité APRÈS le calcul du score de criticité
    par le modèle Random Forest.
    """
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    else:
        return 'LOW'


def severite_vers_priorite(severite):
    """
    Convertit la sévérité calculée par le modèle RF
    en niveau de priorité cohérent pour l'affichage.
    """
    if severite == 'CRITICAL':
        return 'HAUTE'
    elif severite == 'HIGH':
        return 'HAUTE'
    elif severite == 'MEDIUM':
        return 'MOYENNE'
    else:
        return 'BASSE'


# Catalogue : drapeau brut SSLyze -> (nom, description, type, cve, cvss_statique, epss_statique).
# SOURCE UNIQUE du mapping vulnérabilités, partagée par le scan ET la comparaison :
# ajouter une faille ici la rend visible des deux côtés, sans risque de divergence.
def _catalogue_vulns(resultats_bruts):
    protocoles = resultats_bruts.get('protocoles', {}) or {}
    return [
        (protocoles.get('ssl2'),  'SSL 2.0 activé', 'SSL 2.0 est obsolète et présente de graves failles de sécurité', 'Protocole faible', 'CVE-2011-3389', 9.8, 0.95),
        (protocoles.get('ssl3'),  'POODLE - SSL 3.0 activé', 'SSL 3.0 est vulnérable à l attaque POODLE', 'Protocole faible', 'CVE-2014-3566', 9.3, 0.92),
        (protocoles.get('tls10'), 'TLS 1.0 activé', 'TLS 1.0 est obsolète et vulnérable à plusieurs attaques', 'Protocole faible', 'CVE-2011-3389', 7.5, 0.75),
        (protocoles.get('tls11'), 'TLS 1.1 activé', 'TLS 1.1 est déprécié depuis 2021', 'Protocole faible', 'CVE-2015-0204', 5.3, 0.45),
        (resultats_bruts.get('heartbleed'), 'HEARTBLEED', 'Fuite de mémoire critique dans OpenSSL', 'Fuite de données', 'CVE-2014-0160', 9.8, 0.97),
        (resultats_bruts.get('robot'), 'ROBOT Attack', 'Vulnérabilité RSA permettant le déchiffrement', 'Chiffrement faible', 'CVE-2017-13099', 7.5, 0.70),
    ]


def vulns_brutes_depuis_scan(resultats_bruts):
    """Vulnérabilités de base d'une sortie brute SSLyze (nom/description/type/cve +
    cvss/epss statiques), sans appel réseau ni scoring."""
    return [
        {'nom': nom, 'description': desc, 'type': typ, 'cve': cve, 'cvss': cvss, 'epss': epss}
        for actif, nom, desc, typ, cve, cvss, epss in _catalogue_vulns(resultats_bruts) if actif
    ]


def vulns_scorees_locales(resultats_bruts):
    """Vulnérabilités d'un scan scorées localement (Random Forest, sans appel API).
    Utilisé par la comparaison pour rester cohérent avec le scan sans rappeler NVD/FIRST."""
    out = []
    for base in vulns_brutes_depuis_scan(resultats_bruts):
        score = predire_score(base['cvss'], base['epss'], base['type'])
        out.append({**base, 'score_ia': round(score, 2), 'criticite': round(score, 2)})
    return out


def analyser_resultats(resultats_bruts, on_finding=None):
    """
    Analyse les résultats bruts de SSLyze.
    La sévérité ET la priorité sont calculées APRÈS la prédiction
    du score Random Forest — jamais codées en dur.

    on_finding(vuln) : callback optionnel appelé pour chaque vulnérabilité dès
    qu'elle est scorée — sert au streaming SSE (affichage temps réel).
    """
    # Mapping brut partagé, puis enrichissement temps réel (NVD/FIRST) par faille.
    vulnerabilites = []
    for base in vulns_brutes_depuis_scan(resultats_bruts):
        cvss, epss, source = get_metadata_temps_reel(base['cve'], base['cvss'], base['epss'])
        if base['nom'] == 'TLS 1.0 activé':
            cvss = max(cvss, 7.5)       # plancher historique conservé
        vulnerabilites.append({
            'nom'        : base['nom'],
            'description': base['description'],
            'type'       : base['type'],
            'cve'        : base['cve'],
            'cvss'       : cvss,
            'epss'       : epss,
            'source'     : source,
        })

    # ── Score RF → sévérité → priorité (tout cohérent) ───────────────────
    for vuln in vulnerabilites:
        score             = predire_score(vuln['cvss'], vuln['epss'], vuln['type'])
        vuln['criticite'] = round(score, 2)
        vuln['severite']  = determiner_severite(score)
        vuln['priorite']  = severite_vers_priorite(vuln['severite'])
        if on_finding:
            on_finding(vuln)            # streaming temps réel (SSE)

    # ── Trier par score décroissant ───────────────────────────────────────
    return sorted(vulnerabilites, key=lambda x: x['criticite'], reverse=True)


def prioriser(vulnerabilites):
    """Trie les vulnérabilités par score de criticité décroissant"""
    return sorted(vulnerabilites, key=lambda x: x['criticite'], reverse=True)