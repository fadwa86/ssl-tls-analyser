"""P2 — sévérité/priorité (agent.py) et score RF + repli déterministe (modele_rf.py)."""
import pytest

from agent_ia.agent import determiner_severite, severite_vers_priorite
from agent_ia import modele_rf
from agent_ia.modele_rf import predire_score, TYPE_MAP

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('score,attendu', [
    (9.0, 'CRITICAL'), (9.5, 'CRITICAL'),
    (8.99, 'HIGH'), (7.0, 'HIGH'),
    (6.99, 'MEDIUM'), (4.0, 'MEDIUM'),
    (3.99, 'LOW'), (0.0, 'LOW'),
])
def test_determiner_severite_seuils(score, attendu):
    assert determiner_severite(score) == attendu


@pytest.mark.parametrize('sev,prio', [
    ('CRITICAL', 'HAUTE'), ('HIGH', 'HAUTE'),
    ('MEDIUM', 'MOYENNE'), ('LOW', 'BASSE'),
])
def test_severite_vers_priorite(sev, prio):
    assert severite_vers_priorite(sev) == prio


def test_rf_path_renvoie_float_borne():
    # pkl présent -> chemin Random Forest ; on n'assert PAS une valeur exacte.
    s = predire_score(9.8, 0.95, 'Protocole faible')
    assert isinstance(s, float) and 0.0 <= s <= 10.0


def test_repli_formule_exacte(monkeypatch):
    # Force le repli en faisant échouer pickle.load (sans supprimer le pkl,
    # ce qui déclencherait un ré-entraînement lent + écriture disque).
    def _boom(*a, **k):
        raise RuntimeError('pickle indisponible')
    monkeypatch.setattr(modele_rf.pickle, 'load', _boom)
    # repli = (cvss*0.6) + (epss*10*0.4), borné [0,10], arrondi 2.
    assert predire_score(9.8, 0.95, 'X') == 9.68
    assert predire_score(10.0, 1.0, 'X') == 10.0   # 6.0 + 4.0 borné
    assert predire_score(0.0, 0.0, 'X') == 0.0


def test_type_inconnu_ne_crashe_pas():
    assert 'Protocole faible' in TYPE_MAP
    s = predire_score(5.0, 0.5, 'TypeQuiNExistePas')
    assert isinstance(s, float) and 0.0 <= s <= 10.0
