import pickle
import os
import numpy as np
from sklearn.ensemble import RandomForestRegressor

# ── Encodage des features ─────────────────────────────────────────────────────
TYPE_MAP = {
    'Protocole faible' : 0,
    'Fuite de données' : 1,
    'Chiffrement faible': 2
}

# ── Chemin du modèle sauvegardé ───────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'modele_rf.pkl')


def entrainer_modele():
    """
    Entraîne le modèle Random Forest sur le dataset de vulnérabilités SSL/TLS.
    Features : [cvss, epss, type_encoded]  — 3 features
    Target   : score de criticité (0-10)
    """

    # ── Dataset d'entraînement ────────────────────────────────────────────────
    # Format : [cvss, epss, type_encoded]
    X = [
        # Vulnérabilités SSL/TLS réelles
        [9.8, 0.95, 0],   # SSL 2.0    — Protocole faible
        [9.3, 0.92, 0],   # POODLE     — Protocole faible
        [9.8, 0.97, 1],   # HEARTBLEED — Fuite de données
        [7.5, 0.70, 2],   # ROBOT      — Chiffrement faible
        [7.5, 0.75, 0],   # TLS 1.0    — Protocole faible
        [5.3, 0.45, 0],   # TLS 1.1    — Protocole faible

        # Cas synthétiques — Protocole faible (type=0)
        [10.0, 0.99, 0],
        [9.5,  0.90, 0],
        [9.0,  0.85, 0],
        [8.5,  0.80, 0],
        [8.0,  0.78, 0],
        [7.0,  0.60, 0],
        [6.5,  0.55, 0],
        [5.5,  0.45, 0],
        [4.5,  0.35, 0],
        [3.5,  0.25, 0],
        [2.0,  0.10, 0],
        [1.0,  0.05, 0],

        # Cas synthétiques — Fuite de données (type=1)
        [10.0, 0.99, 1],
        [9.5,  0.90, 1],
        [9.0,  0.85, 1],
        [8.5,  0.80, 1],
        [8.0,  0.78, 1],
        [6.5,  0.55, 1],
        [3.0,  0.20, 1],

        # Cas synthétiques — Chiffrement faible (type=2)
        [10.0, 0.99, 2],
        [9.5,  0.90, 2],
        [9.0,  0.85, 2],
        [8.5,  0.80, 2],
        [8.0,  0.78, 2],
        [7.0,  0.60, 2],
        [6.5,  0.55, 2],
        [5.0,  0.40, 2],
        [2.5,  0.15, 2],
        [1.0,  0.05, 2],

        # Cas limites — EPSS élevé mais CVSS bas
        [4.0,  0.85, 0],
        [3.0,  0.75, 2],

        # Cas limites — CVSS élevé mais EPSS bas
        [9.0,  0.10, 0],
        [8.0,  0.05, 1],
    ]

    # ── Scores de criticité cibles ────────────────────────────────────────────
    # Formule de base : (cvss * 0.6) + (epss * 10 * 0.4)
    # Ajustés selon le contexte métier
    y = [
        # Vulnérabilités réelles
        9.5,   # SSL 2.0
        9.2,   # POODLE
        9.7,   # HEARTBLEED
        7.8,   # ROBOT
        7.5,   # TLS 1.0
        5.0,   # TLS 1.1

        # Protocole faible synthétiques
        9.97,
        9.3,
        8.8,
        8.3,
        8.0,
        6.8,
        6.1,
        5.1,
        4.1,
        3.1,
        1.6,
        0.8,

        # Fuite de données synthétiques
        9.97,
        9.3,
        8.8,
        8.3,
        8.0,
        6.1,
        2.8,

        # Chiffrement faible synthétiques
        9.97,
        9.3,
        8.8,
        8.3,
        8.0,
        6.8,
        6.1,
        4.6,
        2.1,
        0.8,

        # Cas limites
        5.8,   # EPSS élevé CVSS bas
        5.0,   # EPSS élevé CVSS bas
        6.4,   # CVSS élevé EPSS bas
        5.0,   # CVSS élevé EPSS bas
    ]

    # ── Entraînement ─────────────────────────────────────────────────────────
    modele = RandomForestRegressor(
        n_estimators   = 100,
        max_depth      = 5,
        min_samples_split = 2,
        min_samples_leaf  = 1,
        random_state   = 42
    )
    modele.fit(X, y)

    # ── Sauvegarde ───────────────────────────────────────────────────────────
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(modele, f)

    print(f"Modèle entraîné et sauvegardé dans {MODEL_PATH}")
    print(f"Score R² sur données d'entraînement : {modele.score(X, y):.4f}")
    return modele


def predire_score(cvss, epss, type_vuln):
    """
    Prédit le score de criticité à partir de 3 features.
    Fallback sur formule simple si modèle indisponible.
    """
    try:
        if not os.path.exists(MODEL_PATH):
            print("[RF] modele_rf.pkl introuvable → ré-entraînement")
            entrainer_modele()

        with open(MODEL_PATH, 'rb') as f:
            modele = pickle.load(f)

        type_encoded = TYPE_MAP.get(type_vuln, 0)
        features     = np.array([[cvss, epss, type_encoded]])
        score        = modele.predict(features)[0]
        score        = max(0.0, min(10.0, float(score)))
        return round(score, 2)

    except Exception as e:
        print(f"[RF] Erreur prédiction : {e} → fallback formule simple")
        # Fallback corrigé — sans severite
        score_fallback = (cvss * 0.6) + (epss * 10 * 0.4)
        score_fallback = max(0.0, min(10.0, score_fallback))
        return round(score_fallback, 2)