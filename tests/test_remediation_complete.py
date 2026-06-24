"""Garde anti-orphelin : chaque nom de finding émettable a une entrée RECOMMANDATIONS
avec une sous-clé 'inconnu' (sinon le PDF/priorisation lève KeyError ou n'affiche aucune
remédiation). Les noms sont dérivés PROGRAMMATIQUEMENT des sources (jamais codés en dur)."""
import pytest

from routes.priorisation import RECOMMANDATIONS
from agent_ia.analyse_ciphers import META_CIPHER
from agent_ia.analyse_certificat import META_CERT
from agent_ia.scanner_multiport import _VULNS_PORT

pytestmark = pytest.mark.unit


def _noms_emettables():
    noms = {m[0] for m in META_CIPHER.values()}
    noms |= {m[0] for m in META_CERT.values()}
    noms |= {t[1] for t in _VULNS_PORT}     # (condition, nom, cve, type, cvss, epss)
    return noms


def test_chaque_nom_a_une_remediation():
    manquants = [n for n in _noms_emettables() if n not in RECOMMANDATIONS]
    assert not manquants, f"noms sans remédiation : {manquants}"


def test_chaque_remediation_a_inconnu():
    sans_inconnu = [n for n in _noms_emettables() if 'inconnu' not in RECOMMANDATIONS.get(n, {})]
    assert not sans_inconnu, f"remédiations sans clé 'inconnu' : {sans_inconnu}"
