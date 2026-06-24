"""P7 — parseur oracle testssl HORS-LIGNE (marqué unit, zéro dépendance binaire).

Réduit par rapport au blueprint « no heavy adds » : pas de testssl.sh installé, pas
de matrice de confusion live. On parse un échantillon JSON SYNTHÉTIQUE (forme du
--jsonfile-pretty) vers notre espace d'étiquettes, et on n'assert que les lignes
réellement présentes dans la fixture. Restaurable en oracle live sur demande.
"""
import json
import os
import re

import pytest

pytestmark = pytest.mark.unit

_FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'testssl_sample.json')

# id testssl -> étiquette dans NOTRE espace (cf. analyse_ciphers / observed).
_MAP_ID = {
    'RC4': 'cipher_rc4',
    'SWEET32': 'cipher_3des',
    'FREAK': 'cipher_export',
    'cipherlist_NULL': 'cipher_null',
    'SSLv2': 'proto_ssl2',
    'SSLv3': 'proto_ssl3',
    'heartbleed': 'heartbleed',
}


def verdicts_testssl(rapport):
    """Liste de findings testssl -> set d'étiquettes. Ignore les id inconnus (pas de KeyError)."""
    labels = set()
    for item in rapport or []:
        idv = item.get('id', '')
        if idv in _MAP_ID:
            labels.add(_MAP_ID[idv])
        if idv == 'LOGJAM':
            m = re.search(r'(\d+)\s*bit', item.get('finding', ''))
            if m:
                labels.add('dh_512' if int(m.group(1)) <= 512 else 'dh_1024')
    return labels


@pytest.fixture
def rapport():
    with open(_FIXTURE, encoding='utf-8') as f:
        return json.load(f)


def test_fixture_forme(rapport):
    assert isinstance(rapport, list) and rapport
    for item in rapport:
        assert 'id' in item and 'severity' in item and 'finding' in item


def test_parse_etiquettes_attendues(rapport):
    labels = verdicts_testssl(rapport)
    assert {'cipher_rc4', 'cipher_3des', 'dh_512', 'proto_ssl3', 'heartbleed'} <= labels


def test_logjam_bit_regex():
    assert verdicts_testssl([{'id': 'LOGJAM', 'finding': '1024 bit', 'severity': 'H'}]) == {'dh_1024'}
    assert verdicts_testssl([{'id': 'LOGJAM', 'finding': 'no bits here', 'severity': 'H'}]) == set()


def test_id_inconnu_ignore():
    assert verdicts_testssl([{'id': 'scanTime', 'finding': '1s', 'severity': 'INFO'}]) == set()
