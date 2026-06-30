"""Miroir + extension du bloc __main__ de agent_ia/agent_multiport.py (source intacte).
Ajoute la couverture des chaînes d'observation downgrade (port 25 vs 587, 143 vs 993),
le différenciateur du projet, non couvert par le bloc inline."""
import pytest

from agent_ia.agent_multiport import (
    analyser_incoherence_multiport, calculer_score_risque_global, _ports_reels,
)

pytestmark = pytest.mark.unit


def _p(port, score, tls, statut='SUCCES'):
    """Helper : port factice avec un finding réel (criticité=score) pour la formule unifiée ;
    'score_risque' conservé pour l'analyse d'incohérence."""
    findings = [{'nom': f'v{port}', 'cve': 'CVE-0000-0001', 'criticite': score,
                 'severite': 'HIGH'}] if score else []
    return {'port': port, 'score_risque': score, 'statut': statut, 'findings': findings,
            'protocoles': {'tls_supported_str': tls, 'preferred': tls.split(',')[0] or None},
            'certificat': {'valid': True}}


# ── Miroir des assertions inline ──────────────────────────────────────────────
def test_incoherence_se_declenche_sur_ecart():
    obs, _ = analyser_incoherence_multiport([_p(993, 8, 'TLS1.1'), _p(443, 1, 'TLS1.3')])
    assert obs


def test_score_global_borne_a_10():
    obs, feats = analyser_incoherence_multiport([_p(993, 8, 'TLS1.1'), _p(443, 1, 'TLS1.3')])
    assert calculer_score_risque_global([_p(993, 8, 'TLS1.1'), _p(443, 1, 'TLS1.3')], feats) <= 10


def test_port_fantome_filtre_pas_d_observation():
    obs2, _ = analyser_incoherence_multiport([_p(993, 8, 'TLS1.1'), _p(443, 0, '')])
    assert obs2 is None


def test_score_global_non_dilue_par_fantome():
    # Formule unifiée (= comparaison) : moyenne + 0,5 par finding réel → 8 + 0,5 = 8,5.
    assert calculer_score_risque_global([_p(993, 8, 'TLS1.1'), _p(443, 0, '')], {}) == 8.5


def test_ports_reels_garde_ssl2_only():
    assert len(_ports_reels([_p(25, 9, 'SSL2'), _p(587, 2, 'TLS1.2')])) == 2


# ── Extensions : chaînes d'observation downgrade (non couvertes par le inline) ─
def test_observation_downgrade_smtp_25_vs_587():
    obs, feats = analyser_incoherence_multiport([_p(25, 9, 'TLS1.0'), _p(587, 1, 'TLS1.3')])
    assert feats['port_25_weak_vs_587'] is True
    assert 'Port 25' in obs and 'SMTP' in obs


def test_observation_downgrade_imap_143_vs_993():
    obs, feats = analyser_incoherence_multiport([_p(143, 9, 'TLS1.0'), _p(993, 1, 'TLS1.3')])
    assert feats['port_143_weak_vs_993'] is True
    assert 'IMAP' in obs


def test_un_seul_port_pas_d_incoherence():
    obs, feats = analyser_incoherence_multiport([_p(443, 5, 'TLS1.2')])
    assert obs is None and feats == {}


def test_ports_reels_exclut_ignore():
    ports = [_p(443, 1, 'TLS1.3'), {'port': 22, 'statut': 'IGNORE', 'score_risque': 0,
                                    'protocoles': {'tls_supported_str': ''}}]
    assert len(_ports_reels(ports)) == 1
