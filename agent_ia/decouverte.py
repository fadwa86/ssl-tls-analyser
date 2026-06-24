"""
Découverte dynamique des ports ouverts et identification du service par bannière.

Pourquoi : le scanner multi-port décidait du protocole à partir du NUMÉRO de port
(table statique). Un service TLS sur un port non standard (HTTPS:8888, SMTP:2525)
était donc ignoré. Ici on scanne les 100 ports TCP les plus courants (liste nmap),
puis on identifie le service réellement présent en lisant sa bannière d'accueil — le
numéro de port n'est qu'un indice. sslyze se charge ensuite de la poignée de main
TLS/STARTTLS, donc on ne sonde pas STARTTLS nous-mêmes.
"""
import socket
import concurrent.futures

# Top 100 ports TCP (nmap --top-ports 100), par fréquence d'apparition.
TOP_100_PORTS = (
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
    8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
    427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028,
    873, 1755, 2717, 4899, 9100, 119, 37,
)

# Ports à TLS implicite (silencieux) : étiquette de service quand aucune bannière.
PORTS_TLS_IMPLICITE = {443: 'HTTPS', 8443: 'HTTPS', 465: 'SMTPS',
                       993: 'IMAPS', 995: 'POP3S', 990: 'FTPS'}

# Logiciels mail reconnaissables dans la bannière (pour la remédiation adaptée).
_LOGICIELS = ('postfix', 'dovecot', 'exim', 'sendmail', 'courier')


def port_ouvert(host, port, timeout=1.5):
    """True si le port TCP accepte une connexion (port réellement ouvert).

    Sert à distinguer un port OUVERT d'un port FERMÉ indépendamment du résultat
    TLS : un port ouvert sans TLS (HTTP en clair, service custom) échoue la poignée
    de main SSLyze mais reste bel et bien ouvert."""
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def decouvrir_ports_ouverts(host, ports=TOP_100_PORTS, timeout=1.0, max_workers=30):
    """Scan TCP connect parallèle ; retourne la liste triée des ports ouverts."""
    def _ouvert(port):
        return port if port_ouvert(host, port, timeout) else None
    ouverts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for r in ex.map(_ouvert, ports):
            if r is not None:
                ouverts.append(r)
    return sorted(ouverts)


def classer_banniere(banniere, port):
    """
    Fonction PURE (sans réseau) : classe un service à partir de sa bannière.
    Retourne (protocole, use_starttls, logiciel) ou None si non-TLS / inconnu.
    # ponytail: on ne vérifie pas STARTTLS nous-mêmes — sslyze le confirme.
    """
    banniere = banniere or ''
    b = banniere.lower()
    logiciel = next((l for l in _LOGICIELS if l in b), '')

    if not banniere.strip():
        # Silencieux : service « client parle en premier » → TLS direct.
        # Étiquette via les ports à TLS implicite connus, sinon HTTPS générique.
        return (PORTS_TLS_IMPLICITE.get(port, 'HTTPS'), False, logiciel)

    if banniere.startswith('220') and ('smtp' in b or 'esmtp' in b or 'mail' in b):
        return ('SMTP', True, logiciel)
    if banniere.startswith('220') and 'ftp' in b:
        return ('FTP', True, logiciel)
    if banniere.startswith('* OK'):        # réponse non taguée IMAP (POP3 = '+OK')
        return ('IMAP', True, logiciel)
    if banniere.startswith('+OK'):
        return ('POP3', True, logiciel)

    # Bannière connue mais non-TLS (SSH, HTTP en clair, etc.) → ignorer.
    return None


def _lire_banniere(host, port, timeout):
    """Lit une fois la bannière d'accueil (256 octets) ; '' si le service est silencieux."""
    # ponytail: un seul recv(256) — toute bannière d'accueil tient dans le 1er segment.
    try:
        with socket.create_connection((host, port), timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode('latin-1', 'ignore')
            except socket.timeout:
                return ''
    except OSError:
        return ''


def identifier_service(host, port, timeout=2.0):
    """Identifie le service d'un port ouvert (voir classer_banniere)."""
    return classer_banniere(_lire_banniere(host, port, timeout), port)


if __name__ == '__main__':
    # Auto-vérification hors-ligne (sans socket) : on teste la logique pure.
    assert classer_banniere('220 mail.x ESMTP Postfix', 25) == ('SMTP', True, 'postfix')
    assert classer_banniere('220 ProFTPD 1.3 Server', 21) == ('FTP', True, '')
    assert classer_banniere('* OK [CAPABILITY] Dovecot ready', 143) == ('IMAP', True, 'dovecot')
    assert classer_banniere('+OK POP3 ready', 110) == ('POP3', True, '')
    assert classer_banniere('', 993) == ('IMAPS', False, '')      # IMAPS silencieux gardé mail
    assert classer_banniere('', 8888) == ('HTTPS', False, '')     # TLS direct port custom
    assert classer_banniere('SSH-2.0-OpenSSH_8.9', 22) is None    # non-TLS ignoré
    print('decouverte.py : auto-vérification OK')
