"""P7 — host_autorise : refus de toute cible hors allowlist (garde des sondes actives)."""
import pytest

from agent_ia.acces import host_autorise, PROTOCOLES_STARTTLS

pytestmark = pytest.mark.unit

_ALLOW = {'mail.local', 'self-host.test'}


@pytest.mark.parametrize('proto', sorted(PROTOCOLES_STARTTLS))
def test_hote_autorise_protocoles_supportes(proto):
    assert host_autorise('mail.local', proto, _ALLOW) is True


def test_hote_hors_allowlist_refuse():
    assert host_autorise('evil.example', 'SMTP', _ALLOW) is False


def test_protocole_non_supporte_refuse():
    assert host_autorise('mail.local', 'LDAP', _ALLOW) is False


@pytest.mark.parametrize('host,allow', [(None, _ALLOW), ('', _ALLOW), ('mail.local', None)])
def test_entrees_invalides_refusees(host, allow):
    assert host_autorise(host, 'SMTP', allow) is False
