"""
Source UNIQUE des findings « chiffrement faible / DH faible / échec de certificat ».
Pur (hors-réseau), partagé par le scan mono-port (agent.py) ET multi-port
(scanner_multiport.py) — un seul endroit produit ces findings, garantissant des
scores identiques des deux côtés.

Imports paresseux de determiner_severite/severite_vers_priorite (depuis agent.py)
pour éviter le cycle agent <-> analyse_findings. Sortie : la forme 8-clés habituelle
{nom,cve,type,cvss,epss,criticite,severite,priorite}. La sévérité vient TOUJOURS du
modèle (predire_score -> determiner_severite), jamais codée en dur.
"""
from agent_ia.modele_rf import predire_score
from agent_ia.analyse_ciphers import classer_faiblesse_cipher, classer_faiblesse_dh, META_CIPHER
from agent_ia.analyse_certificat import META_CERT, CERT_EXPIRE
from agent_ia.classification import est_informatif, SEVERITE_INFO, PRIORITE_INFO


def _construire(label, meta, determiner, prioriser):
    nom, cve, type_v, cvss, epss = meta[label]
    criticite = round(predire_score(cvss, epss, type_v), 2)
    severite = determiner(criticite)
    f = {
        'nom': nom, 'cve': cve, 'type': type_v,
        'cvss': cvss, 'epss': epss, 'criticite': criticite,
        'severite': severite, 'priorite': prioriser(severite),
    }
    if est_informatif(f):                       # cve '-'/absente -> informationnel
        f['severite'] = SEVERITE_INFO
        f['priorite'] = PRIORITE_INFO
    return f


def findings_ciphers(resultats_port):
    """Findings des suites faibles + DH faible (dédupliqués)."""
    from agent_ia.agent import determiner_severite, severite_vers_priorite
    labels = set()
    for d in resultats_port.get('ciphers_details', []) or []:
        lab = classer_faiblesse_cipher(d.get('nom'), d.get('key_size'), d.get('is_anonymous', False))
        if lab:
            labels.add(lab)
        ldh = classer_faiblesse_dh(d.get('ephemeral_type'), d.get('ephemeral_size'))
        if ldh in META_CIPHER:                 # dh_512/dh_1024 ; dh_inconnu exclu
            labels.add(ldh)
    return [_construire(l, META_CIPHER, determiner_severite, severite_vers_priorite)
            for l in sorted(labels)]


def findings_certificat(resultats_port):
    """Findings d'échec de certificat : échecs structurels (echecs[]) + expiration.
    L'expiration (cert['expire'] dans le passé) est la SOURCE UNIQUE de 'Certificat expiré'
    (CWE-298), partagée mono-port/multi-port. Prédicat tz-sûr réutilisé (agent_multiport)."""
    from agent_ia.agent import determiner_severite, severite_vers_priorite
    from agent_ia.agent_multiport import _est_expire
    cert = resultats_port.get('certificat', {}) or {}
    labels = set(cert.get('echecs', []) or [])
    if _est_expire(cert.get('expire')):
        labels.add(CERT_EXPIRE)
    return [_construire(l, META_CERT, determiner_severite, severite_vers_priorite)
            for l in sorted(labels) if l in META_CERT]
