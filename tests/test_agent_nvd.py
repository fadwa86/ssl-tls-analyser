"""P2 — agent.analyser_resultats : enrichissement NVD/FIRST mocké, cache, plancher TLS 1.0,
cohérence des CVE. Aucun appel réseau (get_nvd/get_first monkeypatchés)."""
import pytest

from agent_ia import agent
from agent_ia.agent import (
    analyser_resultats, vulns_brutes_depuis_scan, get_metadata_temps_reel,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def mock_nvd_first(monkeypatch):
    """Renvoie les valeurs statiques telles quelles -> source 'statique', zéro réseau."""
    monkeypatch.setattr(agent, 'get_nvd', lambda cve, cvss: cvss)
    monkeypatch.setattr(agent, 'get_first', lambda cve, epss: epss)


def test_catalogue_cve_tls10_beast():
    v = vulns_brutes_depuis_scan({'protocoles': {'tls10': True}})
    assert v[0]['cve'] == 'CVE-2011-3389'


def test_catalogue_cve_tls11_freak():
    # Mapping intentionnel hérité : TLS 1.1 -> CVE-2015-0204 (collision FREAK documentée).
    v = vulns_brutes_depuis_scan({'protocoles': {'tls11': True}})
    assert v[0]['cve'] == 'CVE-2015-0204'


def test_analyser_resultats_scelle_les_findings(mock_nvd_first):
    res = analyser_resultats({'protocoles': {'ssl3': True}})
    assert len(res) == 1
    f = res[0]
    # Chaque finding porte la forme complète, sévérité issue du modèle.
    for cle in ('nom', 'cve', 'cvss', 'epss', 'criticite', 'severite', 'priorite'):
        assert cle in f
    assert f['severite'] in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}


def test_plancher_tls10(monkeypatch):
    # NVD renvoie un CVSS plus bas que le plancher historique 7.5 -> doit être relevé.
    monkeypatch.setattr(agent, 'get_nvd', lambda cve, cvss: 5.0)
    monkeypatch.setattr(agent, 'get_first', lambda cve, epss: epss)
    res = analyser_resultats({'protocoles': {'tls10': True}})
    tls10 = next(f for f in res if f['nom'] == 'TLS 1.0 activé')
    assert tls10['cvss'] == 7.5


def test_cache_api_source_statique(mock_nvd_first):
    agent._cache_api.clear()
    cvss, epss, source = get_metadata_temps_reel('CVE-2014-0160', 9.8, 0.97)
    assert source == 'statique'
    assert 'CVE-2014-0160' in agent._cache_api


def test_cache_api_temps_reel(monkeypatch):
    agent._cache_api.clear()
    monkeypatch.setattr(agent, 'get_nvd', lambda cve, cvss: 1.0)   # diffère du statique
    monkeypatch.setattr(agent, 'get_first', lambda cve, epss: epss)
    _, _, source = get_metadata_temps_reel('CVE-2099-0001', 9.8, 0.5)
    assert source == 'temps_reel'
