"""Miroir + extension du bloc __main__ de agent_ia/decouverte.py (source intacte)."""
import pytest

from agent_ia.decouverte import classer_banniere

pytestmark = pytest.mark.unit


# ── Miroir des assertions inline ──────────────────────────────────────────────
def test_smtp_postfix():
    assert classer_banniere('220 mail.x ESMTP Postfix', 25) == ('SMTP', True, 'postfix')


def test_ftp_proftpd():
    assert classer_banniere('220 ProFTPD 1.3 Server', 21) == ('FTP', True, '')


def test_imap_dovecot():
    assert classer_banniere('* OK [CAPABILITY] Dovecot ready', 143) == ('IMAP', True, 'dovecot')


def test_pop3():
    assert classer_banniere('+OK POP3 ready', 110) == ('POP3', True, '')


def test_imaps_silencieux():
    assert classer_banniere('', 993) == ('IMAPS', False, '')


def test_tls_direct_port_custom():
    assert classer_banniere('', 8888) == ('HTTPS', False, '')


def test_ssh_non_tls_ignore():
    assert classer_banniere('SSH-2.0-OpenSSH_8.9', 22) is None


# ── Extensions ────────────────────────────────────────────────────────────────
def test_port_proto_1010_fallback_https_3uplet():
    # Port positif TLS 1.0 du blueprint (1010) : bannière vide -> ('HTTPS', False, '').
    # Confirme l'arité 3-tuple (et non 2) que l'intégration consomme.
    assert classer_banniere('', 1010) == ('HTTPS', False, '')


def test_smtps_implicite():
    assert classer_banniere('', 465) == ('SMTPS', False, '')


def test_pop3s_implicite():
    assert classer_banniere('', 995) == ('POP3S', False, '')


def test_smtp_logiciel_exim():
    assert classer_banniere('220 mail ESMTP Exim 4.9', 25) == ('SMTP', True, 'exim')


def test_banniere_none_ne_crashe_pas():
    # Port inconnu sans bannière -> fallback HTTPS générique.
    assert classer_banniere(None, 12345) == ('HTTPS', False, '')
