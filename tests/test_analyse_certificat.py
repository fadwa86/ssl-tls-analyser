"""P5 — classifieur d'échecs de certificat (structurel + texte hostname versionné)
et pont _findings_certificat -> findings 8-clés."""
import pytest

from agent_ia.analyse_certificat import (
    classer_echec_certificat, META_CERT, LABELS_CERT,
    CERT_SELF_SIGNED, CERT_UNTRUSTED, CERT_HOSTNAME, CERT_CHAIN_INCOMPLETE,
)
from agent_ia.scanner_multiport import _findings_certificat, analyser_vulns_port
from agent_ia.modele_rf import TYPE_MAP

pytestmark = pytest.mark.unit

_CLES = {'nom', 'cve', 'type', 'cvss', 'epss', 'criticite', 'severite', 'priorite'}


def test_self_signed_prime_sur_untrusted():
    assert classer_echec_certificat(
        {'issuer_eq_subject': True, 'path_validation_ok': False}) == [CERT_SELF_SIGNED]


def test_untrusted_structurel():
    assert classer_echec_certificat(
        {'issuer_eq_subject': False, 'path_validation_ok': False,
         'validation_error': 'validation failed: candidates exhausted'}) == [CERT_UNTRUSTED]


def test_hostname_seul_pas_untrusted():
    # Cert fiable mais mauvais hôte : hostname SEUL (pas de faux untrusted_root).
    assert classer_echec_certificat(
        {'issuer_eq_subject': False, 'path_validation_ok': False,
         'validation_error': 'leaf certificate has no matching subjectAltName'}) == [CERT_HOSTNAME]


def test_no_san_nest_pas_hostname():
    assert classer_echec_certificat(
        {'issuer_eq_subject': False, 'path_validation_ok': False,
         'validation_error': 'leaf server certificate has no subjectAltName'}) == [CERT_UNTRUSTED]


def test_chain_incomplete_false_seulement():
    assert classer_echec_certificat(
        {'issuer_eq_subject': False, 'path_validation_ok': True,
         'chain_order': False}) == [CERT_CHAIN_INCOMPLETE]


def test_chain_order_none_pas_incomplete():
    assert classer_echec_certificat({'chain_order': None, 'path_validation_ok': True}) == []


def test_certificat_valide_aucun_echec():
    assert classer_echec_certificat(
        {'issuer_eq_subject': False, 'path_validation_ok': True, 'chain_order': True}) == []


def test_robuste_vue_vide_ou_none():
    assert classer_echec_certificat({}) == [] and classer_echec_certificat(None) == []


def test_meta_couvre_toutes_les_etiquettes():
    assert LABELS_CERT <= set(META_CERT)
    for _, (_n, _c, type_v, cvss, epss) in META_CERT.items():
        assert type_v in TYPE_MAP and isinstance(cvss, (int, float)) and isinstance(epss, (int, float))


# ── Pont vers les findings ────────────────────────────────────────────────────
def test_findings_certificat_8_cles():
    port = {'certificat': {'echecs': [CERT_SELF_SIGNED]}}
    f = _findings_certificat(port)
    assert len(f) == 1 and set(f[0]) == _CLES
    assert isinstance(f[0]['epss'], (int, float))


def test_findings_certificat_aucun_echec():
    assert _findings_certificat({'certificat': {}}) == []
    assert _findings_certificat({}) == []


def test_analyser_vulns_port_integre_cert():
    port = {'port': 443, 'protocoles': {}, 'certificat': {'echecs': [CERT_UNTRUSTED]},
            'ciphers_details': []}
    score, findings = analyser_vulns_port(port)
    assert score > 0 and any('non fiable' in f['nom'] for f in findings)
