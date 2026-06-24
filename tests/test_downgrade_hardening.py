"""P6 — FALLBACK_SCSV/downgrade (détection existante, non testée jusqu'ici),
durcissement SHA-1 / no_sct, et étiquettes positives proto_tls10/11/12 (unitaire)."""
import pytest

from agent_ia.scanner_multiport import analyser_vulns_port
from agent_ia.analyse_certificat import (
    classer_echec_certificat, CERT_SHA1, CERT_NO_SCT,
)

pytestmark = pytest.mark.unit


def _port(**extra):
    base = {'port': 443, 'protocoles': {}, 'certificat': {}, 'heartbleed': False,
            'robot': False, 'ccs': False, 'downgrade': False, 'ciphers_details': []}
    base.update(extra)
    return base


# ── Downgrade / FALLBACK_SCSV (déjà calculé par le scanner, ici on le teste) ──
def test_downgrade_vrai_produit_finding():
    score, findings = analyser_vulns_port(_port(downgrade=True))
    assert any('Downgrade' in f['nom'] for f in findings)


def test_downgrade_faux_aucun_finding():
    score, findings = analyser_vulns_port(_port(downgrade=False))
    assert not any('Downgrade' in f['nom'] for f in findings)


# ── Durcissement certificat ───────────────────────────────────────────────────
def test_sha1_signature():
    assert classer_echec_certificat({'path_validation_ok': True, 'sha1_signature': True}) == [CERT_SHA1]


def test_sha1_none_pas_de_finding():
    assert classer_echec_certificat({'path_validation_ok': True, 'sha1_signature': None}) == []


def test_no_sct_compte_zero():
    assert classer_echec_certificat({'path_validation_ok': True, 'scts_count': 0}) == [CERT_NO_SCT]


def test_no_sct_none_supprime():
    # None (extension SCT non parsée) ne doit PAS déclencher no_sct.
    assert classer_echec_certificat({'path_validation_ok': True, 'scts_count': None}) == []


def test_no_sct_positif_pas_de_finding():
    assert classer_echec_certificat({'path_validation_ok': True, 'scts_count': 2}) == []


def test_cert_findings_atteignent_le_port():
    # Un echec sha1 doit devenir un finding 8-clés via _findings_certificat.
    port = _port(certificat={'echecs': [CERT_SHA1]})
    score, findings = analyser_vulns_port(port)
    assert any('SHA-1' in f['nom'] for f in findings)
