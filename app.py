import os
import sys
import ssl
# Console Windows en cp1252 par défaut : un print() contenant '→', '✓', etc. fait
# planter le thread de scan (UnicodeEncodeError). On force la sortie en UTF-8.
for _flux in (sys.stdout, sys.stderr):
    try:
        _flux.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from flask import Flask, redirect
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from models.models import db
db.init_app(app)

from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

# Protection CSRF sur toutes les requêtes POST (formulaires + fetch JSON). Les
# formulaires portent {{ csrf_token() }} ; les appels fetch envoient l'en-tête
# X-CSRFToken. Les flux SSE (GET) ne sont pas concernés.
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

with app.app_context():
    db.create_all()
    print("Tables créées avec succès !")
    
    from models.models import Administrateur
    if not Administrateur.query.filter_by(role='Administrateur').first():
        bcrypt = Bcrypt(app)
        admin = Administrateur(
            nom='Touibi', prenom='Fadwa',
            login='fadwa',
            password=bcrypt.generate_password_hash('fadwa123456').decode('utf-8'),
            email='fadwa.touibi@gmail.com',
            role='Administrateur'
        )
        db.session.add(admin)
        db.session.commit()
        print("✓ Admin initial créé automatiquement")

from routes.auth import auth
from routes.scan import scan_bp
from routes.historique import historique_bp
from routes.priorisation import prio_bp
from routes.rapport import rapport_bp
from routes.profil import profil_bp
from routes.multiport_scan import multiport_bp
from routes.comparison_bp import comparison_bp

app.register_blueprint(auth)
app.register_blueprint(scan_bp)
app.register_blueprint(historique_bp)
app.register_blueprint(prio_bp)
app.register_blueprint(rapport_bp)
app.register_blueprint(profil_bp)
app.register_blueprint(multiport_bp, url_prefix='/multiport')
app.register_blueprint(comparison_bp, url_prefix='/comparison')

@app.route('/')
def index():
    return redirect('/login')

if __name__ == '__main__':
    # HTTPS : certificat auto-signé généré au premier lancement (voir generate_cert.py).
    # Chemins ancrés sur le dossier de app.py (pas le cwd) pour rester indépendants du
    # répertoire de lancement. Pour régénérer le certificat : supprimer cert.pem + key.pem.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert = os.path.join(base_dir, 'cert.pem')
    key = os.path.join(base_dir, 'key.pem')
    if not (os.path.exists(cert) and os.path.exists(key)):
        from generate_cert import generer_cert
        generer_cert(cert, key)

    # Contexte SSL explicite : équivalent à ce que Werkzeug construit depuis (cert, key)
    # mais immunise contre une régression de la conversion tuple -> SSLContext.
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cert, key)

    # threaded=True : chaque connexion SSE garde un thread ouvert ; sans cela un flux
    # bloquerait toutes les autres requêtes sur le serveur de dev.
    app.run(host='127.0.0.1', port=5000, ssl_context=ssl_ctx,
            debug=True, threaded=True)