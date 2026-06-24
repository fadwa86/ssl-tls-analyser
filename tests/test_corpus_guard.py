"""P8 — gardes HORS-LIGNE du corpus (jouées en CI) : aucune étiquette orpheline,
schéma de ligne valide, hôtes propres, ports passables à la découverte."""
import pytest

from tests.data.cibles_blueprint import CIBLES
from tests.observed import TOUTES_ETIQUETTES, WEAK_LABELS
from agent_ia.scanner_multiport import nettoyer_cible

pytestmark = pytest.mark.unit


def test_aucune_etiquette_orpheline():
    utilisees = set()
    for _h, _p, _m, labels, _pol in CIBLES:
        utilisees |= labels
    orphelines = utilisees - TOUTES_ETIQUETTES
    assert not orphelines, f'étiquettes sans producteur : {orphelines}'


@pytest.mark.parametrize('ligne', CIBLES, ids=[c[0] for c in CIBLES])
def test_schema_ligne(ligne):
    assert len(ligne) == 5
    host, port, mode, labels, polarite = ligne
    assert isinstance(host, str) and ':' not in host and '/' not in host
    assert isinstance(port, int) and 0 < port < 65536
    assert mode in {'auto', 'manuel'}
    assert isinstance(labels, set)
    assert polarite in {'cible', 'controle'}


@pytest.mark.parametrize('ligne', CIBLES, ids=[c[0] for c in CIBLES])
def test_host_propre_pour_sni(ligne):
    host = ligne[0]
    assert nettoyer_cible(host) == host    # pas de :port résiduel qui corromprait le SNI


def test_controles_sans_labels_cibles_avec():
    for host, _p, _m, labels, polarite in CIBLES:
        if polarite == 'controle':
            assert labels == set(), f'{host}: contrôle ne doit rien attendre'
        else:
            assert labels, f'{host}: cible doit attendre au moins une étiquette'


def test_etiquettes_cibles_sont_faibles():
    # Toute étiquette attendue d'une 'cible' doit être une étiquette faible.
    for host, _p, _m, labels, polarite in CIBLES:
        if polarite == 'cible':
            assert labels <= WEAK_LABELS, f'{host}: {labels - WEAK_LABELS} non faibles'


def test_ports_non_standards_presents():
    ports = {p for _h, p, _m, _l, _pol in CIBLES}
    assert {1010, 1011} <= ports     # confirme qu'on devra les passer explicitement
