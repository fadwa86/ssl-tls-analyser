"""Utilitaire Server-Sent Events (SSE) partagé par les scans et la comparaison.

Principe : chaque job (scan simple, scan multi-port, comparaison) garde dans son
dict mémoire une liste append-only `evenements`. Le worker en arrière-plan y ajoute
des évènements ; ce flux les diffuse au navigateur et se ferme sur 'done'/'error'.

Contrat d'évènement :
  {'type': 'phase',   'message': str, 'progression': int}   -> avancement
  {'type': 'finding', 'item': {...}}                        -> résultat partiel (live)
  {'type': 'done',    'resultat': {...}}                    -> terminal, rendu final
  {'type': 'error',   'message': str}                       -> terminal
"""
import json
import time
from flask import Response, stream_with_context


def sse_event(obj):
    """Sérialise un évènement au format SSE (`data: ...\\n\\n`)."""
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


def flux_evenements(etat_getter, intervalle=0.4, timeout=600):
    """Construit la réponse SSE qui rejoue puis suit la liste `evenements` d'un job.

    etat_getter() -> dict | None : l'état courant du job (avec 'evenements' + 'statut').
    Rejoue tout l'historique (reconnexion = aucune perte), puis pousse les nouveaux
    évènements jusqu'à un statut terminal. Se ferme alors : le client DOIT appeler
    EventSource.close() sur 'done'/'error' pour éviter la reconnexion automatique.
    """
    @stream_with_context
    def generer():
        yield ": ok\n\n"                      # commentaire initial -> force le flush
        idx = 0
        debut = time.monotonic()
        while True:
            etat = etat_getter()
            if etat is None:
                yield sse_event({'type': 'error', 'message': 'Job introuvable'})
                return
            evenements = etat.get('evenements', [])
            while idx < len(evenements):
                yield sse_event(evenements[idx])
                idx += 1
            if etat.get('statut') in ('TERMINE', 'ERREUR'):
                return
            if time.monotonic() - debut > timeout:      # garde-fou anti-connexion zombie
                yield sse_event({'type': 'error', 'message': 'Délai dépassé'})
                return
            time.sleep(intervalle)

    return Response(generer(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',   # désactive le buffering (proxys type nginx)
        'Connection': 'keep-alive',
    })
