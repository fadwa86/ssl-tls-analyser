"""
Conformité TLS : note SSL-Labs A–F, évaluation PCI-DSS v4.0 / NIST SP 800-52 et
durée de validité restante d'un certificat. Logique pure + auto-vérification.
"""
from datetime import datetime, timezone


def calculer_grade_tls(findings):
    """Note A–F à partir de la pire sévérité des findings (clés `severite`)."""
    sev = {f.get('severite') for f in findings}
    if 'CRITICAL' in sev:
        return 'F'
    if 'HIGH' in sev:
        return 'C'
    if 'MEDIUM' in sev:
        return 'B'
    return 'A'


def _port_conforme(p):
    """Règles booléennes de conformité sur un port (dict issu de details_bruts)."""
    proto = p.get('protocoles', {})
    cert = p.get('certificat', {})
    faiblesses = []
    for cle, libelle in (('ssl2', 'SSL 2.0'), ('ssl3', 'SSL 3.0'),
                         ('tls10', 'TLS 1.0'), ('tls11', 'TLS 1.1')):
        if proto.get(cle):
            faiblesses.append(libelle)
    if p.get('heartbleed'):
        faiblesses.append('Heartbleed')
    if p.get('robot'):
        faiblesses.append('ROBOT')
    tls_moderne = bool(proto.get('tls12') or proto.get('tls13'))
    cert_ok = cert.get('valid') is not False           # None toléré (port non-HTTPS)
    conforme = (not faiblesses) and tls_moderne and cert_ok
    # ponytail: PCI-DSS et NIST partagent ici la même base « TLS moderne, pas de faille ».
    return {'port': p.get('port'), 'pci_dss': conforme, 'nist': conforme,
            'regles_echec': faiblesses}


def evaluer_conformite(resultats_ports):
    """Conformité par port + globale (pire cas : un seul port non conforme = échec)."""
    per_port = [_port_conforme(p) for p in resultats_ports if p.get('protocoles')]
    pci = all(x['pci_dss'] for x in per_port) if per_port else False
    nist = all(x['nist'] for x in per_port) if per_port else False
    return {'pci_dss': pci, 'nist': nist, 'per_port': per_port}


def calculer_duree_restante(expire):
    """(label, is_expired) depuis une date ISO ou un datetime. Gère None / expiré / négatif."""
    if not expire:
        return ('N/A', None)
    try:
        dt = datetime.fromisoformat(expire) if isinstance(expire, str) else expire
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        jours = (dt - datetime.now(timezone.utc)).days
    except (ValueError, TypeError):
        return ('N/A', None)
    if jours < 0:
        return (f'EXPIRÉ depuis {abs(jours)} j', True)
    return (f'{jours} jours restants', False)


if __name__ == '__main__':
    assert calculer_grade_tls([{'severite': 'CRITICAL'}]) == 'F'
    assert calculer_grade_tls([{'severite': 'LOW'}]) == 'A'
    assert calculer_grade_tls([]) == 'A'
    port_faible = {'port': 25, 'protocoles': {'tls10': True, 'tls12': True}, 'certificat': {'valid': True}}
    port_sain = {'port': 443, 'protocoles': {'tls12': True, 'tls13': True}, 'certificat': {'valid': True}}
    assert evaluer_conformite([port_faible])['pci_dss'] is False
    assert evaluer_conformite([port_sain])['pci_dss'] is True
    assert calculer_duree_restante(None) == ('N/A', None)
    assert calculer_duree_restante('2000-01-01T00:00:00')[1] is True
    print('conformite.py : auto-vérification OK')
