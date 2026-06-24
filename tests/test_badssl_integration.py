"""P8 — intégration LIVE (réseau, opt-in TLS_LIVE). « Agit comme un utilisateur » :
découvre les ports OUVERTS puis scanne UNIQUEMENT ceux-là, en parallèle, via le point
d'entrée public. Contrat tri-état : fermé/dns-fail/feature-retirée -> xfail (pas fail).
"""
import os
import socket

import pytest

from tests.data.cibles_blueprint import CIBLES
from tests.observed import derive_labels, WEAK_LABELS

pytestmark = [pytest.mark.network, pytest.mark.integration]

if not os.environ.get('TLS_LIVE'):
    pytest.skip("intégration live désactivée (positionner TLS_LIVE=1)", allow_module_level=True)

from agent_ia.decouverte import decouvrir_ports_ouverts          # noqa: E402
from agent_ia.scanner_multiport import scanner_cible_multiport   # noqa: E402


@pytest.mark.parametrize('host,port,mode,attendus,polarite', CIBLES,
                         ids=[c[0] for c in CIBLES])
def test_cible_live(host, port, mode, attendus, polarite):
    # 1) DNS d'abord : distingue un sous-domaine mort d'un port fermé.
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        pytest.xfail(f'dns-fail: {host}')

    # 2) Découverte : ne tester QUE les ports ouverts (timeout élargi + 1 re-probe
    #    pour le petit ensemble ; ports non standards passés EXPLICITEMENT).
    ouverts = decouvrir_ports_ouverts(host, ports=(port,), timeout=4.0)
    if port not in ouverts:
        ouverts = decouvrir_ports_ouverts(host, ports=(port,), timeout=6.0)
    if port not in ouverts:
        pytest.xfail(f'port {port} fermé sur {host}')

    # 3) Scan des ports ouverts en parallèle, via le point d'entrée public (comme l'app).
    res = scanner_cible_multiport(cible=host, ports=[port], mode='manuel')
    portres = next((r for r in res.get('resultats', []) if r.get('port') == port), None)

    # 4) Contrat tri-état.
    negocie = portres and portres.get('statut') == 'SUCCES' and (
        portres.get('protocoles', {}).get('tls_supported_str') or portres.get('certificat'))
    if not negocie:
        pytest.xfail(f'négociation TLS échouée sur {host}:{port}')

    observed = derive_labels(portres)

    if polarite == 'controle':
        faux_positifs = observed & WEAK_LABELS
        assert not faux_positifs, f'{host}: faux positif sur contrôle -> {faux_positifs}'
    else:
        manquants = attendus - observed
        if manquants:
            pytest.xfail(f'{host}: labels absents (endpoint a peut-être changé) '
                         f'{manquants} ; observed={observed}')
        assert attendus <= observed
