"""
Fixtures partagées. Point clé : on force une base SQLite sur fichier AVANT tout
import de `app`, car app.py exécute db.create_all() + le seed admin à l'import
(cf. CLAUDE.md « Database gotcha »). Sans cette surcharge, la collecte pytest
tenterait de joindre MySQL.
"""
import os
import sys
import tempfile

import pytest

# Racine du projet (dossier contenant config.py / app.py / agent_ia) sur sys.path,
# pour que `import config`, `import app`, `agent_ia.*` résolvent quel que soit le cwd.
_RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RACINE not in sys.path:
    sys.path.insert(0, _RACINE)

import config

# SQLite SUR FICHIER (pas :memory:, qui est par-connexion et perdrait le seed
# créé à l'import sous une autre connexion).
_DB_FICHIER = os.path.join(tempfile.gettempdir(), 'tls_analyzer_test.db')
config.Config.SQLALCHEMY_DATABASE_URI = f'sqlite:///{_DB_FICHIER}'


@pytest.fixture(scope='session')
def app():
    """L'app Flask, importée APRÈS la surcharge d'URI (db.create_all()+seed à l'import)."""
    import app as app_module
    return app_module.app


@pytest.fixture(autouse=True)
def _vider_cache_api():
    """Le cache _cache_api d'agent.py est un dict global : on le vide entre tests
    pour éviter qu'un (cvss,epss,source) mémorisé fausse un test ultérieur."""
    try:
        from agent_ia import agent
        agent._cache_api.clear()
    except Exception:
        pass
    yield
