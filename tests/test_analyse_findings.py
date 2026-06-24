"""STEP 2-5 — source unique analyse_findings + émission mono-port dans analyser_resultats.
Vérifie : délégation multi-port identique, nouveaux findings émis côté mono-port avec
description+source, originaux préservés, et parité de score mono-port == multi-port."""
import pytest

from agent_ia import agent
from agent_ia.agent import analyser_resultats
from agent_ia.analyse_findings import findings_ciphers, findings_certificat
from agent_ia import scanner_multiport as sm

pytestmark = pytest.mark.unit

_CLES = {'nom', 'cve', 'type', 'cvss', 'epss', 'criticite', 'severite', 'priorite'}


def _rc4_port():
    return {'ciphers_details': [{'nom': 'TLS_RSA_WITH_RC4_128_MD5', 'key_size': 128,
                                 'is_anonymous': False, 'ephemeral_type': None, 'ephemeral_size': None}]}


@pytest.fixture
def mock_nvd(monkeypatch):
    monkeypatch.setattr(agent, 'get_nvd', lambda cve, cvss: cvss)
    monkeypatch.setattr(agent, 'get_first', lambda cve, epss: epss)


# ── Source unique ─────────────────────────────────────────────────────────────
def test_findings_ciphers_rc4():
    f = findings_ciphers(_rc4_port())
    assert len(f) == 1 and set(f[0]) == _CLES and 'RC4' in f[0]['nom']


def test_findings_certificat_selfsigned():
    f = findings_certificat({'certificat': {'echecs': ['cert_self_signed']}})
    assert len(f) == 1 and 'auto-signé' in f[0]['nom']


def test_delegation_multiport_identique():
    port = _rc4_port()
    assert sm._findings_ciphers(port) == findings_ciphers(port)
    cert = {'certificat': {'echecs': ['cert_self_signed']}}
    assert sm._findings_certificat(cert) == findings_certificat(cert)


# ── Émission mono-port ────────────────────────────────────────────────────────
def test_mono_port_emet_nouveaux(mock_nvd):
    brut = {'protocoles': {'ssl3': True},
            'certificat': {'echecs': ['cert_self_signed']}, **_rc4_port()}
    res = analyser_resultats(brut)
    noms = [v['nom'] for v in res]
    assert 'POODLE - SSL 3.0 activé' in noms          # original conservé
    assert any('RC4' in n for n in noms)              # nouveau cipher
    assert any('auto-signé' in n for n in noms)       # nouveau cert
    for v in res:
        assert 'description' in v and 'source' in v   # clés mono-port présentes


def test_mono_port_regression_originaux(mock_nvd):
    res = analyser_resultats({'protocoles': {'ssl3': True}})
    assert [v['nom'] for v in res] == ['POODLE - SSL 3.0 activé']


def test_mono_port_parite_score_multiport(mock_nvd):
    port = _rc4_port()
    res = analyser_resultats({'protocoles': {}, 'certificat': {}, **port})
    rc4 = next(v for v in res if 'RC4' in v['nom'])
    mp = findings_ciphers(port)[0]
    assert rc4['criticite'] == mp['criticite'] and rc4['severite'] == mp['severite']


def test_mono_port_streaming_on_finding(mock_nvd):
    recus = []
    analyser_resultats({'protocoles': {}, 'certificat': {}, **_rc4_port()},
                       on_finding=lambda v: recus.append(v['nom']))
    assert any('RC4' in n for n in recus)             # nouveau finding streamé via SSE


def test_json_roundtrip_et_reanalyse(mock_nvd):
    """donneesSSL est json.dumps'é puis re-analysé (historique/priorisation/rapport) :
    les findings cipher/DH/cert doivent survivre et réapparaître (DH bytearray exclu)."""
    import json
    brut = {'protocoles': {'tls10': True},
            'certificat': {'echecs': ['cert_self_signed'], 'expire': '2999-01-01T00:00:00'},
            'ciphers_details': [{'nom': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'key_size': 128,
                                 'is_anonymous': False, 'ephemeral_type': 'DH', 'ephemeral_size': 512}]}
    raw = json.loads(json.dumps(brut))                # survit la persistance
    noms = [v['nom'] for v in analyser_resultats(raw)]
    assert any('Diffie-Hellman 512' in n for n in noms)
    assert any('auto-signé' in n for n in noms)


def test_diff_voit_les_nouveaux_findings():
    """vulns_scorees_locales (source du diff) inclut désormais cipher/cert avec score_ia."""
    from agent_ia.agent import vulns_scorees_locales
    out = vulns_scorees_locales({'protocoles': {}, 'certificat': {'echecs': ['cert_self_signed']},
                                 **_rc4_port()})
    noms = [v['nom'] for v in out]
    assert any('RC4' in n for n in noms) and any('auto-signé' in n for n in noms)
    assert all('score_ia' in v for v in out)          # clé attendue par comparison_bp
