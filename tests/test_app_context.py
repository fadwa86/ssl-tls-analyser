"""P0 — l'app démarre sous SQLite fichier (sans MySQL) et le seed admin est présent."""
import pytest

pytestmark = pytest.mark.unit


def test_app_demarre_sous_sqlite(app):
    assert app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite')


def test_seed_admin_present(app):
    with app.app_context():
        from models.models import Administrateur
        assert Administrateur.query.filter_by(login='fadwa').first() is not None
