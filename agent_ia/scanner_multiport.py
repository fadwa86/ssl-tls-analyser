from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ServerNetworkConfiguration, RobotScanResultEnum
from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.plugins.scan_commands import ScanCommand
import urllib3
import gc
import concurrent.futures
from datetime import datetime, timezone

from agent_ia.decouverte import decouvrir_ports_ouverts, identifier_service, port_ouvert
from agent_ia.scanner import detecter_serveur
from agent_ia.agent import determiner_severite, severite_vers_priorite
from agent_ia.analyse_certificat import classer_echec_certificat

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
        'echecs': [],
        'vue_validation': None,
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

            # Projection de validation + échecs. Try ISOLÉ : une erreur ici ne doit
            # JAMAIS effacer valid/expire/cn/issuer extraits ci-dessus.
            try:
                pvrs = list(getattr(deployment, 'path_validation_results', []) or [])
                ok = any(getattr(p, 'was_validation_successful', False) for p in pvrs) if pvrs else None
                err = None
                for p in pvrs:
                    if not getattr(p, 'was_validation_successful', False):
                        err = getattr(p, 'validation_error', None)
                        if err:
                            break
                vue = {
                    'issuer_eq_subject': cert.issuer == cert.subject,
                    'path_validation_ok': ok,
                    'validation_error': str(err) if err else None,
                    'chain_order': getattr(deployment, 'received_chain_has_valid_order', None),
                    'anchor_present': getattr(deployment, 'received_chain_contains_anchor_certificate', None),
                    'sha1_signature': getattr(deployment, 'verified_chain_has_sha1_signature', None),
                    'scts_count': getattr(deployment, 'leaf_certificate_signed_certificate_timestamps_count', None),
                }
                cert_info['vue_validation'] = vue
                cert_info['echecs'] = classer_echec_certificat(vue)
            except Exception:
                pass

    except Exception as e:
        cert_info['error'] = str(e)

    return cert_info


def _collecter_ciphers(resultats_port, acceptees):
    """Ajoute les suites acceptées (nom + détails JSON-sûrs) — sur TOUTES les versions.
    Ne stocke JAMAIS les champs bytearray (prime/generator/public_bytes) : on ne garde
    que type_name (str) et size (int) de la clé éphémère -> json.dumps reste sûr.
    Préserve ciphers_acceptees (liste de noms) consommée par le PDF."""
    for c in acceptees or []:
        try:
            nom = c.cipher_suite.name
        except Exception:
            continue
        resultats_port['ciphers_acceptees'].append(nom)
        eph = getattr(c, 'ephemeral_key', None)
        resultats_port['ciphers_details'].append({
            'nom': nom,
            'key_size': getattr(c.cipher_suite, 'key_size', None),
            'is_anonymous': bool(getattr(c.cipher_suite, 'is_anonymous', False)),
            'ephemeral_type': getattr(eph, 'type_name', None) if eph is not None else None,
            'ephemeral_size': getattr(eph, 'size', None) if eph is not None else None,
        })


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
        'ciphers_details':   [],
    }

    try:
        # network_timeout/max_retries relevés : le défaut sslyze (5 s) coupe la
        # poignée de main sur connexion lente/latente → "Connection timed out",
        # 0 protocole, 0 finding alors que le TCP passe. cf. diag_cert.py.
        if use_starttls and protocole in STARTTLS_MAP:
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=host,
                tls_opportunistic_encryption=STARTTLS_MAP[protocole],
                network_timeout=15,
                network_max_retries=5
            )
        else:
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=host,
                network_timeout=15,
                network_max_retries=5
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
            # Collecte des suites sur TOUTES les versions : RC4/export/3DES/DHE-export
            # ne négocient que sur SSL3/TLS1.0/1.1 — les ignorer = faux négatifs garantis.
            try:
                if sr.ssl_2_0_cipher_suites and sr.ssl_2_0_cipher_suites.result:
                    acc = sr.ssl_2_0_cipher_suites.result.accepted_cipher_suites
                    if acc:
                        protocols['ssl2'] = True
                        _collecter_ciphers(resultats_port, acc)
            except: pass

            try:
                if sr.ssl_3_0_cipher_suites and sr.ssl_3_0_cipher_suites.result:
                    acc = sr.ssl_3_0_cipher_suites.result.accepted_cipher_suites
                    if acc:
                        protocols['ssl3'] = True
                        _collecter_ciphers(resultats_port, acc)
            except: pass

            try:
                if sr.tls_1_0_cipher_suites and sr.tls_1_0_cipher_suites.result:
                    acc = sr.tls_1_0_cipher_suites.result.accepted_cipher_suites
                    if acc:
                        protocols['tls10'] = True
                        _collecter_ciphers(resultats_port, acc)
            except: pass

            try:
                if sr.tls_1_1_cipher_suites and sr.tls_1_1_cipher_suites.result:
                    acc = sr.tls_1_1_cipher_suites.result.accepted_cipher_suites
                    if acc:
                        protocols['tls11'] = True
                        _collecter_ciphers(resultats_port, acc)
            except: pass

            try:
                if sr.tls_1_2_cipher_suites and sr.tls_1_2_cipher_suites.result:
                    acceptees = sr.tls_1_2_cipher_suites.result.accepted_cipher_suites
                    if acceptees:
                        protocols['tls12'] = True
                        _collecter_ciphers(resultats_port, acceptees)
            except: pass

            try:
                if sr.tls_1_3_cipher_suites and sr.tls_1_3_cipher_suites.result:
                    acceptees = sr.tls_1_3_cipher_suites.result.accepted_cipher_suites
                    if acceptees:
                        protocols['tls13'] = True
                        _collecter_ciphers(resultats_port, acceptees)
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


def _findings_ciphers(resultats_port):
    """Délégation vers la source unique agent_ia.analyse_findings (import paresseux)."""
    from agent_ia.analyse_findings import findings_ciphers
    return findings_ciphers(resultats_port)


def _findings_certificat(resultats_port):
    """Délégation vers la source unique agent_ia.analyse_findings (import paresseux)."""
    from agent_ia.analyse_findings import findings_certificat
    return findings_certificat(resultats_port)


def analyser_vulns_port(resultats_port):
    """
    Construit la liste des findings d'un port et le score moyen (0-10).
    Chaque finding suit les mêmes clés que agent.py (nom, cve, type, cvss, epss,
    criticite, severite, priorite). La sévérité vient TOUJOURS du modèle RF
    (predire_score → determiner_severite), jamais codée en dur.
    """
    from agent_ia.modele_rf import predire_score
    from agent_ia.classification import est_informatif, SEVERITE_INFO, PRIORITE_INFO

    # L'expiration n'est PLUS un déclencheur ici : 'Certificat expiré' (CWE-298) est émis
    # par findings_certificat (source unique). _certificat_expire reste défini (consommé
    # par tests/observed.py + tests unitaires) mais n'est plus appelé ici.
    findings = []
    protocoles = resultats_port.get('protocoles', {})
    contexte = {**resultats_port, 'protocoles': protocoles}
    for condition, nom, cve, type_v, cvss, epss in _VULNS_PORT:
        if not condition(contexte):
            continue
        criticite = round(predire_score(cvss, epss, type_v), 2)
        severite = determiner_severite(criticite)
        f = {
            'nom': nom, 'cve': cve, 'type': type_v,
            'cvss': cvss, 'epss': epss, 'criticite': criticite,
            'severite': severite, 'priorite': severite_vers_priorite(severite),
        }
        if est_informatif(f):                  # 'TLS Downgrade' (cve '-') -> informationnel
            f['severite'] = SEVERITE_INFO
            f['priorite'] = PRIORITE_INFO
        findings.append(f)

    # Findings supplémentaires : chiffrement faible / DH faible / échecs+expiration de certificat.
    findings += _findings_ciphers(resultats_port)
    findings += _findings_certificat(resultats_port)

    if not findings:
        return 0.0, []
    # Score = moyenne des VRAIES vulns uniquement (les informationnels n'inflent pas le risque).
    reels = [f for f in findings if f['severite'] != SEVERITE_INFO]
    score = round(min(sum(f['criticite'] for f in reels) / len(reels), 10.0), 2) if reels else 0.0
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
                'statut': 'IGNORE', 'ouvert': True, 'score_risque': 0.0, 'findings': []}

    protocole, use_starttls, logiciel = service
    resultats_port = scanner_port_sslyze(host, port, protocole, use_starttls)
    score, findings = analyser_vulns_port(resultats_port)
    resultats_port['score_risque'] = score
    resultats_port['findings']     = findings
    resultats_port['logiciel']     = logiciel
    resultats_port['classe']       = 'starttls' if use_starttls else 'direct_tls'
    # 'ouvert' = port réellement ouvert (TLS OK, ou TLS échoué mais TCP accepté).
    # Le statut SSLyze ne suffit pas : un port ouvert sans TLS échoue le handshake
    # (ERREUR) tout en restant ouvert → on le reconnaît par un connect TCP direct.
    resultats_port['ouvert'] = resultats_port['statut'] == 'SUCCES' or port_ouvert(host, port)
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