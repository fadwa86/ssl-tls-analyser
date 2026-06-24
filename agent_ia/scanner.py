from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ServerNetworkConfiguration
from sslyze.plugins.scan_commands import ScanCommand
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def nettoyer_cible(cible):
    """
    Nettoie la cible saisie par l'utilisateur.
    Accepte : https://example.com, example.com, 192.168.1.1
    """
    cible = cible.strip()
    cible = cible.replace('https://', '').replace('http://', '')
    cible = cible.split('/')[0]  # supprimer le chemin
    cible = cible.split(':')[0]  # supprimer le port s'il est inclus
    return cible


def est_adresse_ip(cible):
    """Vérifie si la cible est une adresse IP"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, cible))


def _details_ciphers(acceptees):
    """Détails JSON-sûrs des suites acceptées (nom + taille + clé éphémère).
    Ne stocke aucun bytearray -> json.dumps(resultats_bruts) reste sûr.
    # ponytail: petite duplication assumée de scanner_multiport._collecter_ciphers ;
    # la version mono-port n'alimente pas 'ciphers_acceptees' (inutile au PDF ReportLab)."""
    out = []
    for c in acceptees or []:
        try:
            nom = c.cipher_suite.name
        except Exception:
            continue
        eph = getattr(c, 'ephemeral_key', None)
        out.append({
            'nom': nom,
            'key_size': getattr(c.cipher_suite, 'key_size', None),
            'is_anonymous': bool(getattr(c.cipher_suite, 'is_anonymous', False)),
            'ephemeral_type': getattr(eph, 'type_name', None) if eph is not None else None,
            'ephemeral_size': getattr(eph, 'size', None) if eph is not None else None,
        })
    return out


def scanner_cible(hostname, port=443):
    try:
        hostname = nettoyer_cible(hostname)

        # Si c'est une IP, pas de SNI (Server Name Indication)
        if est_adresse_ip(hostname):
            server_location = ServerNetworkLocation(
                hostname=hostname,
                port=port
            )
        else:
            server_location = ServerNetworkLocation(
                hostname=hostname,
                port=port
            )

        # Timeout relevé (défaut sslyze = 5 s) : sur connexion lente la poignée
        # de main échoue → "Connection timed out" et 0 finding. cf. scanner_multiport.
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=hostname,
                network_timeout=15,
                network_max_retries=5
            ),
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.CERTIFICATE_INFO,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        resultats_bruts = {
            'hostname':   hostname,
            'port':       port,
            'type_cible': 'ip' if est_adresse_ip(hostname) else 'domaine',
            'protocoles': {
                'ssl2':  False,
                'ssl3':  False,
                'tls10': False,
                'tls11': False,
                'tls12': False,
                'tls13': False,
            },
            'certificat': {},
            'heartbleed': False,
            'robot':      False,
            'ciphers_details': [],
        }

        for result in scanner.get_results():
            if result.scan_result is None:
                continue

            scan = result.scan_result

            # Protocoles + collecte des suites sur TOUTES les versions (RC4/export/3DES/
            # DHE-export ne négocient que sur SSL3/TLS1.0/1.1 — les ignorer = faux négatifs).
            try:
                r = scan.ssl_2_0_cipher_suites
                if r.result is not None:
                    acc = r.result.accepted_cipher_suites
                    resultats_bruts['protocoles']['ssl2'] = len(acc) > 0
                    resultats_bruts['ciphers_details'] += _details_ciphers(acc)
            except:
                pass

            try:
                r = scan.ssl_3_0_cipher_suites
                if r.result is not None:
                    acc = r.result.accepted_cipher_suites
                    resultats_bruts['protocoles']['ssl3'] = len(acc) > 0
                    resultats_bruts['ciphers_details'] += _details_ciphers(acc)
            except:
                pass

            try:
                r = scan.tls_1_0_cipher_suites
                if r.result is not None:
                    acc = r.result.accepted_cipher_suites
                    resultats_bruts['protocoles']['tls10'] = len(acc) > 0
                    resultats_bruts['ciphers_details'] += _details_ciphers(acc)
            except:
                pass

            try:
                r = scan.tls_1_1_cipher_suites
                if r.result is not None:
                    acc = r.result.accepted_cipher_suites
                    resultats_bruts['protocoles']['tls11'] = len(acc) > 0
                    resultats_bruts['ciphers_details'] += _details_ciphers(acc)
            except:
                pass

            try:
                r = scan.tls_1_2_cipher_suites
                if r.result is not None:
                    acc = r.result.accepted_cipher_suites
                    resultats_bruts['protocoles']['tls12'] = len(acc) > 0
                    resultats_bruts['ciphers_details'] += _details_ciphers(acc)
            except:
                pass

            try:
                r = scan.tls_1_3_cipher_suites
                if r.result is not None:
                    acc = r.result.accepted_cipher_suites
                    resultats_bruts['protocoles']['tls13'] = len(acc) > 0
                    resultats_bruts['ciphers_details'] += _details_ciphers(acc)
            except:
                pass

            # Heartbleed
            try:
                r = scan.heartbleed
                if r.result is not None:
                    resultats_bruts['heartbleed'] = r.result.is_vulnerable_to_heartbleed
            except:
                pass

            # ROBOT — ne flaguer QUE les verdicts réellement vulnérables (évite les
            # faux positifs sur serveurs modernes sans RSA / résultats incohérents).
            try:
                from sslyze.plugins.robot.implementation import RobotScanResultEnum
                r = scan.robot
                if r.result is not None:
                    resultats_bruts['robot'] = r.result.robot_result in (
                        RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                        RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
                    )
            except:
                pass

            # Certificat — détail complet + échecs, via la source unique multi-port
            # (import paresseux : scanner_multiport importe scanner -> éviter le cycle).
            try:
                r = scan.certificate_info
                if r.result is not None:
                    from agent_ia.scanner_multiport import extract_certificate_info
                    certificat = extract_certificate_info(r.result)
                    # Alias hérités de la forme mono-port historique (zéro coût, sûreté).
                    certificat['valide']     = certificat.get('valid')
                    certificat['expiration'] = certificat.get('expire')
                    resultats_bruts['certificat'] = certificat
            except:
                pass

        # Détecter le serveur web
        resultats_bruts['serveur'] = detecter_serveur(hostname)

        return resultats_bruts

    except Exception as e:
        return {'erreur': str(e)}


def detecter_serveur(hostname):
    """Détecte automatiquement le type de serveur web — supporte IP et domaine"""
    try:
        hostname = nettoyer_cible(hostname)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        response = None

        # Tentative 1 — HTTPS avec session requests
        try:
            session = requests.Session()
            session.verify = False
            response = session.get(
                f'https://{hostname}',
                timeout=5,
                headers=headers,
                allow_redirects=True
            )
        except Exception as e1:
            print(f"HTTPS échoué: {e1}")

            # Tentative 2 — HTTP simple
            try:
                response = requests.get(
                    f'http://{hostname}',
                    timeout=3,
                    headers=headers,
                    allow_redirects=True,
                    verify=False
                )
            except Exception as e2:
                print(f"HTTP échoué: {e2}")

                # Tentative 3 — SSL permissif (utile pour les IPs avec certs auto-signés)
                try:
                    import ssl
                    import urllib.request
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                    req = urllib.request.Request(
                        f'https://{hostname}',
                        headers=headers
                    )
                    with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                        server = resp.headers.get('Server', '').lower()
                        return _identifier_serveur(server)
                except Exception as e3:
                    print(f"Contexte SSL permissif échoué: {e3}")
                    return {
                        'type':    'inconnu',
                        'version': 'Non détecté',
                        'detecte': False
                    }

        if response:
            server     = response.headers.get('Server', '').lower()
            powered_by = response.headers.get('X-Powered-By', '').lower()
            print(f"Server header : {server}")
            print(f"X-Powered-By  : {powered_by}")
            return _identifier_serveur(server)

        return {'type': 'inconnu', 'version': 'Non détecté', 'detecte': False}

    except Exception as e:
        print(f"Erreur détection serveur: {e}")
        return {'type': 'inconnu', 'version': 'Non détecté', 'detecte': False}


def _identifier_serveur(server_header):
    """
    Identifie le type de serveur à partir du header Server.
    Factorisé pour éviter la duplication de code.
    """
    server = server_header.lower() if server_header else ''

    if 'nginx' in server:
        return {'type': 'nginx',     'version': server, 'detecte': True}
    elif 'apache' in server:
        return {'type': 'apache',    'version': server, 'detecte': True}
    elif 'iis' in server or 'microsoft' in server:
        return {'type': 'iis',       'version': server, 'detecte': True}
    elif 'lighttpd' in server:
        return {'type': 'lighttpd',  'version': server, 'detecte': True}
    elif 'caddy' in server:
        return {'type': 'caddy',     'version': server, 'detecte': True}
    elif 'tomcat' in server:
        return {'type': 'tomcat',    'version': server, 'detecte': True}
    else:
        return {
            'type':    'inconnu',
            'version': server if server else 'Non divulgué',
            'detecte': False
        }
