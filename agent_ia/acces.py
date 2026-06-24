"""
Garde d'autorisation pour les sondes ACTIVES/intrusives (injection STARTTLS, probes
de downgrade). Le blueprint impose de REFUSER tout hôte hors allowlist (self-host +
cibles explicitement autorisées) — point d'éthique et de défendabilité du mémoire.

Module pur et SANS dépendance (pas d'import sslyze/scanner) : il doit rester
importable et testable hors-ligne. On redéclare la petite liste de protocoles
STARTTLS plutôt que d'importer STARTTLS_MAP (qui tirerait sslyze).
"""

PROTOCOLES_STARTTLS = frozenset({'SMTP', 'IMAP', 'POP3', 'FTP'})


def host_autorise(host, protocole, allowlist):
    """True seulement si l'hôte est dans l'allowlist ET le protocole est une cible
    STARTTLS supportée. Tout le reste (hôte inconnu, LDAP, None) est refusé."""
    if not host or host not in (allowlist or ()):
        return False
    return protocole in PROTOCOLES_STARTTLS


if __name__ == '__main__':
    al = {'mail.local', 'self-host.test'}
    assert host_autorise('mail.local', 'SMTP', al) is True
    assert host_autorise('mail.local', 'IMAP', al) is True
    assert host_autorise('evil.example', 'SMTP', al) is False
    assert host_autorise('mail.local', 'LDAP', al) is False   # protocole non supporté
    assert host_autorise(None, 'SMTP', al) is False
    assert host_autorise('mail.local', 'SMTP', None) is False
    print('acces.py : auto-vérification OK')
