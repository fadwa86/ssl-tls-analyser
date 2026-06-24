"""
Classement « vraie vulnérabilité » vs « informationnel » d'un finding.

Module FEUILLE (aucune dépendance projet → aucun cycle) : la règle ne dépend que de
l'identifiant porté par le finding. Un finding est une VRAIE vulnérabilité s'il porte
un identifiant (CVE-… ou CWE-…) ; sans identifiant (cve '-', '' ou absente) il est
INFORMATIF : affiché partout (vues, historique, rapports) avec une étiquette dédiée,
mais NON comptabilisé (compteurs, statut « Vulnérable », grade TLS, score de risque).
"""

SEVERITE_INFO = 'INFORMATIF'
PRIORITE_INFO = 'INFORMATIF'


def est_informatif(finding):
    """True si le finding n'a pas d'identifiant CVE/CWE (cve '-', '' , None ou absente)."""
    cve = (finding or {}).get('cve')
    return cve in ('-', '', None)


if __name__ == '__main__':
    assert est_informatif({'cve': '-'}) is True
    assert est_informatif({'cve': ''}) is True
    assert est_informatif({'cve': None}) is True
    assert est_informatif({}) is True                       # clé absente
    assert est_informatif({'cve': 'CVE-2013-2566'}) is False
    assert est_informatif({'cve': 'CWE-298'}) is False
    print('classification.py : auto-vérification OK')
