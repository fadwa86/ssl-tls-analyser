"""Classement réel vs informationnel : CVE/CWE = réel, cve '-' = informatif.
Cert-validity (incl. expiré) = RÉEL via CWE ; SHA-1/no-SCT = informationnel.
Score de port = moyenne des réels uniquement (informationnels exclus, sans ZeroDivision)."""
import pytest

from agent_ia.classification import est_informatif
from agent_ia.analyse_findings import findings_certificat
from agent_ia.analyse_certificat import (
    META_CERT, CERT_EXPIRE, CERT_SELF_SIGNED, CERT_UNTRUSTED, CERT_HOSTNAME,
    CERT_CHAIN_INCOMPLETE, CERT_SHA1, CERT_NO_SCT,
)
from agent_ia.agent import severite_vers_priorite
from agent_ia.scanner_multiport import analyser_vulns_port

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('cve,info', [
    ('CVE-2013-2566', False), ('CWE-298', False), ('CWE-295', False),
    ('-', True), ('', True), (None, True),
])
def test_est_informatif(cve, info):
    assert est_informatif({'cve': cve}) is info


def test_est_informatif_cle_absente():
    assert est_informatif({}) is True


def test_cert_validity_reelles_via_cwe():
    for lab in (CERT_SELF_SIGNED, CERT_UNTRUSTED, CERT_HOSTNAME, CERT_CHAIN_INCOMPLETE, CERT_EXPIRE):
        _nom, cve, *_ = META_CERT[lab]
        assert cve.startswith('CWE-') and est_informatif({'cve': cve}) is False


def test_hardening_informationnels():
    for lab in (CERT_SHA1, CERT_NO_SCT):
        _nom, cve, *_ = META_CERT[lab]
        assert est_informatif({'cve': cve}) is True


def test_findings_certificat_expire_passe():
    f = findings_certificat({'certificat': {'expire': '2000-01-01T00:00:00'}})
    exp = [x for x in f if x['nom'] == 'Certificat expiré']
    assert len(exp) == 1 and exp[0]['cve'] == 'CWE-298' and exp[0]['severite'] != 'INFORMATIF'


def test_findings_certificat_expire_futur_rien():
    f = findings_certificat({'certificat': {'expire': '2999-01-01T00:00:00'}})
    assert not any(x['nom'] == 'Certificat expiré' for x in f)


def test_self_signed_reel():
    f = findings_certificat({'certificat': {'echecs': [CERT_SELF_SIGNED]}})
    assert len(f) == 1 and f[0]['cve'] == 'CWE-295' and f[0]['severite'] != 'INFORMATIF'


def test_sha1_informatif():
    f = findings_certificat({'certificat': {'echecs': [CERT_SHA1]}})
    assert len(f) == 1 and f[0]['severite'] == 'INFORMATIF' and f[0]['priorite'] == 'INFORMATIF'


def _port(details):
    return {'port': 443, 'protocoles': {}, 'certificat': {}, 'ciphers_details': details}


def test_port_informationnel_seul_score_zero():
    # DES seul (cve '-') -> informatif : score 0.0 (pas de ZeroDivision) mais finding présent.
    s, f = analyser_vulns_port(_port([{'nom': 'TLS_RSA_WITH_DES_CBC_SHA', 'key_size': 56,
                                       'is_anonymous': False, 'ephemeral_type': None, 'ephemeral_size': None}]))
    assert s == 0.0 and len(f) == 1 and f[0]['severite'] == 'INFORMATIF'


def test_port_reel_plus_informatif_score_reel_seul():
    s, f = analyser_vulns_port(_port([
        {'nom': 'TLS_RSA_WITH_RC4_128_MD5', 'key_size': 128, 'is_anonymous': False, 'ephemeral_type': None, 'ephemeral_size': None},
        {'nom': 'TLS_RSA_WITH_DES_CBC_SHA', 'key_size': 56, 'is_anonymous': False, 'ephemeral_type': None, 'ephemeral_size': None}]))
    rc4 = next(x for x in f if 'RC4' in x['nom'])
    assert s == rc4['criticite']          # moyenne des réels = RC4 seul


def test_severite_vers_priorite_informatif():
    assert severite_vers_priorite('INFORMATIF') == 'INFORMATIF'
