"""Miroir + extension du bloc __main__ de agent_ia/conformite.py (source intacte)."""
import pytest

from agent_ia.conformite import (
    calculer_grade_tls, evaluer_conformite, calculer_duree_restante,
)

pytestmark = pytest.mark.unit

_PORT_FAIBLE = {'port': 25, 'protocoles': {'tls10': True, 'tls12': True}, 'certificat': {'valid': True}}
_PORT_SAIN = {'port': 443, 'protocoles': {'tls12': True, 'tls13': True}, 'certificat': {'valid': True}}


# ── Miroir des assertions inline ──────────────────────────────────────────────
def test_grade_critical_donne_F():
    assert calculer_grade_tls([{'severite': 'CRITICAL'}]) == 'F'


def test_grade_low_donne_A():
    assert calculer_grade_tls([{'severite': 'LOW'}]) == 'A'


def test_grade_vide_donne_A():
    assert calculer_grade_tls([]) == 'A'


def test_conformite_port_faible_non_pci():
    assert evaluer_conformite([_PORT_FAIBLE])['pci_dss'] is False


def test_conformite_port_sain_pci():
    assert evaluer_conformite([_PORT_SAIN])['pci_dss'] is True


def test_duree_restante_none():
    assert calculer_duree_restante(None) == ('N/A', None)


def test_duree_restante_passe_est_expire():
    assert calculer_duree_restante('2000-01-01T00:00:00')[1] is True


# ── Extensions ────────────────────────────────────────────────────────────────
def test_grade_high_donne_C():
    assert calculer_grade_tls([{'severite': 'HIGH'}]) == 'C'


def test_grade_medium_donne_B():
    assert calculer_grade_tls([{'severite': 'MEDIUM'}]) == 'B'


def test_grade_prend_la_pire_severite():
    assert calculer_grade_tls([{'severite': 'LOW'}, {'severite': 'CRITICAL'}]) == 'F'


def test_conformite_port_sain_nist():
    assert evaluer_conformite([_PORT_SAIN])['nist'] is True


def test_conformite_vide_non_conforme():
    res = evaluer_conformite([])
    assert res['pci_dss'] is False and res['nist'] is False


def test_duree_restante_futur_non_expire():
    label, expire = calculer_duree_restante('2999-01-01T00:00:00')
    assert expire is False and 'restant' in label


def test_duree_restante_invalide_renvoie_na():
    assert calculer_duree_restante('pas-une-date') == ('N/A', None)
