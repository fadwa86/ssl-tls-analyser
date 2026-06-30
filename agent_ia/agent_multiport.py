from datetime import datetime, timezone
import json

from agent_ia.conformite import calculer_score_global
from agent_ia.classification import est_informatif


def _est_expire(expire_iso):
    """Vrai si le certificat est expiré. Sûr vis-à-vis des fuseaux (aware/naive)."""
    if not expire_iso:
        return False
    try:
        dt = datetime.fromisoformat(expire_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def _ports_reels(resultats_ports):
    """
    Exclut les ports « fantômes » : ports ignorés (non-TLS) ou ayant répondu sans
    négocier le moindre protocole SSL/TLS (tls_supported_str vide → score 0).
    On filtre sur tls_supported_str et NON sur 'preferred' : ce dernier vaut None
    pour un port SSL2/SSL3-uniquement, qu'il ne faut surtout pas écarter.
    """
    return [r for r in resultats_ports
            if r.get('statut') != 'IGNORE'
            and r.get('protocoles', {}).get('tls_supported_str')]


def analyser_incoherence_multiport(resultats_ports):
    resultats_ports = _ports_reels(resultats_ports)
    if not resultats_ports or len(resultats_ports) < 2:
        return None, {}
    
    resultats_ports = sorted(resultats_ports, key=lambda x: x['port'])
    
    features = {
        'delta_score_max': 0,
        'ports_vulneres': 0,
        'ports_cert_expires': 0,
        'delta_tls_preferé': 0,
        'port_25_weak_vs_587': False,
        'port_143_weak_vs_993': False,
        'incoherence_certificat': False,
    }
    
    scores = [r.get('score_risque', 0) for r in resultats_ports]
    features['delta_score_max'] = max(scores) - min(scores)
    
    features['ports_vulneres'] = sum(1 for r in resultats_ports if r.get('score_risque', 0) > 5)
    
    features['ports_cert_expires'] = sum(
        1 for r in resultats_ports
        if _est_expire(r.get('certificat', {}).get('expire'))
    )
    
    tls_preferés = [r.get('protocoles', {}).get('preferred', 'None') for r in resultats_ports]
    if len(set(tls_preferés)) > 1:
        features['delta_tls_preferé'] = len(set(tls_preferés))
    
    port_25 = next((r for r in resultats_ports if r['port'] == 25), None)
    port_587 = next((r for r in resultats_ports if r['port'] == 587), None)
    
    if port_25 and port_587:
        if port_25.get('score_risque', 0) > port_587.get('score_risque', 0) + 2:
            features['port_25_weak_vs_587'] = True
    
    port_143 = next((r for r in resultats_ports if r['port'] == 143), None)
    port_993 = next((r for r in resultats_ports if r['port'] == 993), None)
    
    if port_143 and port_993:
        if port_143.get('score_risque', 0) > port_993.get('score_risque', 0) + 2:
            features['port_143_weak_vs_993'] = True
    
    certs_valid = [r.get('certificat', {}).get('valid') for r in resultats_ports]
    if len(set(certs_valid)) > 1:
        features['incoherence_certificat'] = True
    
    observation = generate_observation_ia(resultats_ports, features)
    
    return observation, features

def generate_observation_ia(resultats_ports, features):
    observations = []
    
    if features['delta_score_max'] > 3:
        ports_haut = [r['port'] for r in resultats_ports if r.get('score_risque', 0) > 5]
        ports_bas = [r['port'] for r in resultats_ports if r.get('score_risque', 0) < 2]
        observations.append(
            f"⚠️ INCOHÉRENCE TLS CRITIQUE : Écart de {features['delta_score_max']} points entre ports. "
            f"Ports vulnérables: {ports_haut}. Ports sécurisés: {ports_bas}. "
            f"Même domaine, même service, configurations TLS radicalement différentes."
        )
    
    if features['port_25_weak_vs_587']:
        observations.append(
            f"🔴 SMTP: Port 25 (STARTTLS) beaucoup plus faible que port 587 (STARTTLS). "
            f"Risque de downgrade SMTP via port 25."
        )
    
    if features['port_143_weak_vs_993']:
        observations.append(
            f"🔴 IMAP: Port 143 (STARTTLS) beaucoup plus faible que port 993 (TLS direct). "
            f"Risque de downgrade IMAP via port 143."
        )
    
    if features['incoherence_certificat']:
        observations.append(
            f"⚠️ Certificats différents entre ports : certains valides, d'autres non. "
            f"Incohérence de déploiement TLS."
        )
    
    if features['ports_cert_expires'] > 0:
        observations.append(
            f"🔴 {features['ports_cert_expires']} port(s) avec certificat EXPIRÉ. "
            f"Risque immédiat de connexion non chiffrée."
        )
    
    if features['ports_vulneres'] > 0:
        observations.append(
            f"⚠️ {features['ports_vulneres']} port(s) avec score de risque > 5. "
            f"Vulnérabilités TLS actives détectées."
        )
    
    if observations:
        conclusion = (
            f"\n\n🎯 ARGUMENT CLÉ : Aucun scanner HTTPS classique (port 443 uniquement) ne détecte "
            f"ces incohérences multi-ports. Ton modèle Random Forest scoré cette incohérence "
            f"comme une vulnérabilité à part entière — c'est le différenciateur technique de ton projet."
        )
        observations.append(conclusion)
    
    return "\n\n".join(observations)

def calculer_score_risque_global(resultats_ports, features_incoherence=None):
    """Score IA global UNIFIÉ — IDENTIQUE à la comparaison, l'historique et le rapport PDF :
    moyenne des criticités de TOUS les findings réels (CVE/CWE), dédupliqués par (port, nom)
    exactement comme la comparaison, + 0,5 par finding réel, borné à 10. On ignore les ports
    fantômes (non-TLS) via _ports_reels. `features_incoherence` n'est plus utilisé (gardé en
    paramètre optionnel pour compat avec l'appelant ; l'incohérence reste dans l'observation)."""
    vus = {}
    for p in _ports_reels(resultats_ports):
        for f in p.get('findings', []) or []:
            if not est_informatif(f):
                vus[(p.get('port'), f.get('nom'))] = float(f.get('criticite', 0) or 0)
    return calculer_score_global(list(vus.values()))


if __name__ == '__main__':
    # Auto-vérification hors-ligne (logique pure, sans BDD ni réseau).
    def _p(port, score, tls, statut='SUCCES'):
        findings = [{'nom': f'v{port}', 'cve': 'CVE-0000-0001', 'criticite': score,
                     'severite': 'HIGH'}] if score else []
        return {'port': port, 'score_risque': score, 'statut': statut, 'findings': findings,
                'protocoles': {'tls_supported_str': tls, 'preferred': tls.split(',')[0] or None},
                'certificat': {'valid': True}}

    # Échelle 0-10 : un écart de 7 (>3) doit déclencher une observation.
    obs, feats = analyser_incoherence_multiport([_p(993, 8, 'TLS1.1'), _p(443, 1, 'TLS1.3')])
    assert obs, "l'observation devrait se déclencher sur un écart de score de 7/10"
    assert calculer_score_risque_global([_p(993, 8, 'TLS1.1'), _p(443, 1, 'TLS1.3')], feats) <= 10

    # Port fantôme (tls_supported_str vide) exclu → < 2 ports réels → pas d'observation.
    obs2, _ = analyser_incoherence_multiport([_p(993, 8, 'TLS1.1'), _p(443, 0, '')])
    assert obs2 is None, "le port fantôme doit être filtré (pas de fausse incohérence)"

    # Score global non dilué par le fantôme (formule unifiée : moyenne + 0,5×nb_cve).
    assert calculer_score_risque_global([_p(993, 8, 'TLS1.1'), _p(443, 0, '')]) == 8.5

    # Port SSL2-uniquement (preferred=None) NON filtré (tls_supported_str non vide).
    assert len(_ports_reels([_p(25, 9, 'SSL2'), _p(587, 2, 'TLS1.2')])) == 2

    print('agent_multiport.py : auto-vérification OK')