from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ServerNetworkConfiguration, RobotScanResultEnum
from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.plugins.scan_commands import ScanCommand
import urllib3
import gc
import concurrent.futures
from datetime import datetime, timezone

from agent_ia.decouverte import decouvrir_ports_ouverts, identifier_service
from agent_ia.scanner import detecter_serveur
from agent_ia.agent import determiner_severite, severite_vers_priorite

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT_PROTOCOL_MAP = {
    25:   ('SMTP',  True),
    465:  ('SMTPS', False),
    587:  ('SMTP',  True),
    143:  ('IMAP',  True),
    993:  ('IMAPS', False),
    110:  ('POP3',  True),
    995:  ('POP3S', False),
    443:  ('HTTPS', False),
    8443: ('HTTPS', False),
    21:   ('FTP',   True),
}

STARTTLS_MAP = {
    'SMTP': ProtocolWithOpportunisticTlsEnum.SMTP,
    'IMAP': ProtocolWithOpportunisticTlsEnum.IMAP,
    'POP3': ProtocolWithOpportunisticTlsEnum.POP3,
    'FTP':  ProtocolWithOpportunisticTlsEnum.FTP,
}

DEFAULT_PORTS = [25, 443, 587, 143, 993, 110, 995]

# Scans sslyze lancés en parallèle (le scan par port domine le temps total).
# Modéré : chaque scan sslyze ouvre déjà plusieurs connexions en interne.
MAX_WORKERS_SCAN = 6


def nettoyer_cible(cible):
    if cible is None:
        return None
    cible = cible.strip().lower()
    cible = cible.replace('https://', '').replace('http://', '')
    cible = cible.replace('/', '')
    return cible


def extract_certificate_info(cert_result):
    cert_info = {
        'valid':  None,
        'expire': None,
        'cn':     None,
        'issuer': None,
        'signature_algo': None,
    }
    try:
        if cert_result.certificate_deployments:
            deployment = cert_result.certificate_deployments[0]
            cert = deployment.received_certificate_chain[0]

            # Validité = chaîne vérifiée ET certificat non expiré
            now = datetime.now(timezone.utc)
            cert_info['valid'] = (
                deployment.verified_certificate_chain is not None
                and len(deployment.verified_certificate_chain) > 0
            )

            if hasattr(cert, 'not_valid_after_utc'):
                expire_dt = cert.not_valid_after_utc
            elif hasattr(cert, 'not_valid_after'):
                expire_dt = cert.not_valid_after
            else:
                expire_dt = None

            if expire_dt:
                if expire_dt.tzinfo is None:
                    expire_dt = expire_dt.replace(tzinfo=timezone.utc)
                cert_info['expire'] = expire_dt.isoformat()

            try:
                from cryptography.x509.oid import NameOID
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cert_info['cn'] = cn[0].value if cn else None
            except:
                cert_info['cn'] = str(cert.subject)

            try:
                cert_info['issuer'] = str(cert.issuer)
            except:
                pass

            # Algorithme de signature (pour la section technique PCI-DSS).
            try:
                algo = getattr(cert, 'signature_hash_algorithm', None)
                cert_info['signature_algo'] = algo.name if algo else None
            except:
                pass

    except Exception as e:
        cert_info['error'] = str(e)

    return cert_info


def scanner_port_sslyze(host, port, protocole, use_starttls=False):
    resultats_port = {
        'port':             port,
        'protocole':        protocole,
        'starttls_utilise': use_starttls,
        'statut':           'ERREUR',
        'erreur':           None,
        'protocoles': {
            'ssl2': False, 'ssl3': False,
            'tls10': False, 'tls11': False,
            'tls12': False, 'tls13': False,
            'preferred': None,
            'tls_supported_str': ''
        },
        'certificat':  {},
        'heartbleed':  False,
        'robot':       False,
        'ccs':         False,
        'downgrade':   False,
        'ciphers_acceptees': [],
    }

    try:
        if use_starttls and protocole in STARTTLS_MAP:
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=host,
                tls_opportunistic_encryption=STARTTLS_MAP[protocole]
            )
        else:
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=host
            )

        network_location = ServerNetworkLocation(
            hostname=host,
            port=port
        )

        scan_request = ServerScanRequest(
            server_location=network_location,
            network_configuration=network_config,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.TLS_FALLBACK_SCSV,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        protocols = {
            'ssl2': False, 'ssl3': False,
            'tls10': False, 'tls11': False,
            'tls12': False, 'tls13': False,
        }

        for result in scanner.get_results():
            if result.scan_result is None:
                resultats_port['erreur'] = 'Scan échoué'
                return resultats_port

            sr = result.scan_result

            # ✅ Accès direct aux attributs
            try:
                if sr.ssl_2_0_cipher_suites and sr.ssl_2_0_cipher_suites.result:
                    if sr.ssl_2_0_cipher_suites.result.accepted_cipher_suites:
                        protocols['ssl2'] = True
            except: pass

            try:
                if sr.ssl_3_0_cipher_suites and sr.ssl_3_0_cipher_suites.result:
                    if sr.ssl_3_0_cipher_suites.result.accepted_cipher_suites:
                        protocols['ssl3'] = True
            except: pass

            try:
                if sr.tls_1_0_cipher_suites and sr.tls_1_0_cipher_suites.result:
                    if sr.tls_1_0_cipher_suites.result.accepted_cipher_suites:
                        protocols['tls10'] = True
            except: pass

            try:
                if sr.tls_1_1_cipher_suites and sr.tls_1_1_cipher_suites.result:
                    if sr.tls_1_1_cipher_suites.result.accepted_cipher_suites:
                        protocols['tls11'] = True
            except: pass

            try:
                if sr.tls_1_2_cipher_suites and sr.tls_1_2_cipher_suites.result:
                    acceptees = sr.tls_1_2_cipher_suites.result.accepted_cipher_suites
                    if acceptees:
                        protocols['tls12'] = True
                        resultats_port['ciphers_acceptees'] += [c.cipher_suite.name for c in acceptees]
            except: pass

            try:
                if sr.tls_1_3_cipher_suites and sr.tls_1_3_cipher_suites.result:
                    acceptees = sr.tls_1_3_cipher_suites.result.accepted_cipher_suites
                    if acceptees:
                        protocols['tls13'] = True
                        resultats_port['ciphers_acceptees'] += [c.cipher_suite.name for c in acceptees]
            except: pass

            try:
                if sr.certificate_info and sr.certificate_info.result:
                    resultats_port['certificat'] = extract_certificate_info(
                        sr.certificate_info.result
                    )
            except: pass

            try:
                if sr.heartbleed and sr.heartbleed.result:
                    resultats_port['heartbleed'] = sr.heartbleed.result.is_vulnerable_to_heartbleed
            except: pass

            try:
                if sr.robot and sr.robot.result:
                    # Ne flaguer QUE les verdicts réellement vulnérables. Les états
                    # NOT_VULNERABLE_RSA_NOT_SUPPORTED (serveur moderne sans RSA) et
                    # UNKNOWN_INCONSISTENT_RESULTS (probes incohérentes) ne sont PAS
                    # des vulnérabilités → évite les faux positifs ROBOT.
                    resultats_port['robot'] = sr.robot.result.robot_result in (
                        RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                        RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
                    )
            except: pass

            try:
                if sr.openssl_ccs_injection and sr.openssl_ccs_injection.result:
                    resultats_port['ccs'] = sr.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection
            except: pass

            try:
                if sr.tls_fallback_scsv and sr.tls_fallback_scsv.result:
                    resultats_port['downgrade'] = not sr.tls_fallback_scsv.result.supports_fallback_scsv
            except: pass

        # Résumé protocoles
        preferred = None
        if protocols['tls13']:   preferred = 'TLS1.3'
        elif protocols['tls12']: preferred = 'TLS1.2'
        elif protocols['tls11']: preferred = 'TLS1.1'
        elif protocols['tls10']: preferred = 'TLS1.0'

        protocols['preferred'] = preferred
        protocols['tls_supported_str'] = ','.join([
            k.upper() for k, v in protocols.items()
            if v and k != 'preferred'
        ])

        resultats_port['protocoles'] = protocols
        resultats_port['statut']     = 'SUCCES'

    except Exception as e:
        resultats_port['statut'] = 'ERREUR'
        resultats_port['erreur'] = str(e)

    return resultats_port


# Métadonnées des vulnérabilités détectables sur un port (mêmes CVE/CVSS/EPSS
# et mêmes noms que agent.py::analyser_resultats → la remédiation et le PDF
# consomment la même structure de finding).
_VULNS_PORT = [
    # (condition, nom, cve, type, cvss, epss)
    (lambda r: r['protocoles'].get('ssl2'),  'SSL 2.0 activé',          'CVE-2011-3389', 'Protocole faible', 9.8, 0.95),
    (lambda r: r['protocoles'].get('ssl3'),  'POODLE - SSL 3.0 activé', 'CVE-2014-3566', 'Protocole faible', 9.3, 0.92),
    (lambda r: r['protocoles'].get('tls10'), 'TLS 1.0 activé',          'CVE-2011-3389', 'Protocole faible', 7.5, 0.75),
    (lambda r: r['protocoles'].get('tls11'), 'TLS 1.1 activé',          'CVE-2015-0204', 'Protocole faible', 5.3, 0.45),
    (lambda r: r.get('heartbleed'),          'HEARTBLEED',              'CVE-2014-0160', 'Fuite de données', 9.8, 0.97),
    (lambda r: r.get('robot'),               'ROBOT Attack',            'CVE-2017-13099', 'Chiffrement faible', 7.5, 0.70),
    (lambda r: r.get('ccs'),                 'CCS Injection',           'CVE-2014-0224', 'Chiffrement faible', 7.5, 0.65),
    (lambda r: r.get('downgrade'),           'TLS Downgrade',           '-',             'Protocole faible', 5.0, 0.50),
]


def _certificat_expire(resultats_port):
    cert = resultats_port.get('certificat', {})
    if not cert.get('expire'):
        return False
    try:
        dt = datetime.fromisoformat(cert['expire'])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except Exception:
        return False


def analyser_vulns_port(resultats_port):
    """
    Construit la liste des findings d'un port et le score moyen (0-10).
    Chaque finding suit les mêmes clés que agent.py (nom, cve, type, cvss, epss,
    criticite, severite, priorite). La sévérité vient TOUJOURS du modèle RF
    (predire_score → determiner_severite), jamais codée en dur.
    """
    from agent_ia.modele_rf import predire_score

    declencheurs = list(_VULNS_PORT)
    if _certificat_expire(resultats_port):
        declencheurs.append((lambda r: True, 'Certificat expiré', '-', 'Protocole faible', 7.0, 0.60))

    findings = []
    protocoles = resultats_port.get('protocoles', {})
    contexte = {**resultats_port, 'protocoles': protocoles}
    for condition, nom, cve, type_v, cvss, epss in declencheurs:
        if not condition(contexte):
            continue
        criticite = round(predire_score(cvss, epss, type_v), 2)
        severite = determiner_severite(criticite)
        findings.append({
            'nom': nom, 'cve': cve, 'type': type_v,
            'cvss': cvss, 'epss': epss, 'criticite': criticite,
            'severite': severite, 'priorite': severite_vers_priorite(severite),
        })

    if not findings:
        return 0.0, []
    score = round(min(sum(f['criticite'] for f in findings) / len(findings), 10.0), 2)
    return score, findings


def _scanner_un_port(host, port):
    """
    Scan complet d'un port (détection dynamique du service + sslyze + score).
    Exécuté dans un worker du pool de threads — ne touche aucun état partagé.
    """
    service = identifier_service(host, port)
    if service is None:
        # Port ouvert mais non-TLS (SSH, HTTP en clair…) : signalé, pas analysé.
        return {'port': port, 'protocole': 'non-TLS', 'classe': 'non_tls',
                'statut': 'IGNORE', 'score_risque': 0.0, 'findings': []}

    protocole, use_starttls, logiciel = service
    resultats_port = scanner_port_sslyze(host, port, protocole, use_starttls)
    score, findings = analyser_vulns_port(resultats_port)
    resultats_port['score_risque'] = score
    resultats_port['findings']     = findings
    resultats_port['logiciel']     = logiciel
    resultats_port['classe']       = 'starttls' if use_starttls else 'direct_tls'
    return resultats_port


def scanner_cible_multiport(cible, ports=None, mode='auto',
                            progress_callback=None, decouverte_callback=None):
    """
    mode='auto'   : découverte des ports ouverts (top 100) puis détection dynamique
                    du service par bannière — gère les ports non standard.
    mode='manuel' : scanne la liste `ports` fournie (toujours via détection dynamique).
    """
    cible_nettoyée = nettoyer_cible(cible)
    if not cible_nettoyée:
        return {'erreur': 'Cible invalide', 'resultats': []}

    # On NE résout PAS l'hôte en IP : sslyze/socket résolvent le nom, et le SNI
    # doit être le nom d'hôte saisi (pas l'IP). cf. correctif SNI.
    if mode == 'auto':
        ports = decouvrir_ports_ouverts(cible_nettoyée)
    elif ports is None:
        ports = DEFAULT_PORTS

    if not ports:
        return {'cible': cible_nettoyée, 'ports_ouverts': [], 'resultats': [],
                'message': 'Aucun port ouvert détecté'}

    # La barre de progression se cale sur le nombre RÉEL de ports à scanner.
    if decouverte_callback:
        decouverte_callback(ports)

    # Scan des ports EN PARALLÈLE : le scan sslyze par port (~10-15 s) domine le temps
    # total. Les workers font le scan ; la collecte + le progress_callback restent dans
    # CE thread (via as_completed) → pas de mutation concurrente de l'état (pas de verrou).
    resultats_totaux = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS_SCAN, len(ports))) as ex:
        futures = [ex.submit(_scanner_un_port, cible_nettoyée, p) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            resultats_port = fut.result()
            resultats_totaux.append(resultats_port)
            if progress_callback:
                progress_callback(resultats_port['port'], resultats_port)

    resultats_totaux.sort(key=lambda r: r['port'])  # ordre d'affichage stable

    # Détection du serveur web une seule fois, après le scan, sur un VRAI 443/8443
    # (port « fantôme » mail sans web → 0 protocole → on saute, ~14 s économisées).
    serveur = None
    for r in resultats_totaux:
        if r['port'] in (443, 8443) and r.get('protocoles', {}).get('tls_supported_str'):
            serveur = detecter_serveur(cible_nettoyée)
            break

    gc.collect()

    return {
        'cible':         cible_nettoyée,
        'ports_ouverts': ports,
        'serveur':       serveur or {'type': 'inconnu', 'version': 'Non détecté', 'detecte': False},
        'resultats':     resultats_totaux
    }