import secrets
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import (
    generate_rsa_keys,
    sign,
    verify_signature,
    serialize,
    measure_time,
    pubkey_to_bytes
)

class AuthServer:
    """
    Sistema di Autenticazione (SA).
    WP2 Sezione 4.2: Verifica l'identità reale degli elettori, accerta il diritto al voto,
    verifica il Proof-of-Possession sulla chiave effimera e rilascia il Certificato Pseudonimo Cp.
    NON conosce mai i voti (Garantisce lo Pseudo-anonimato [SEC-2]).
    """

    def __init__(self, id_elezione: str):
        # Chiavi del SA (PUSA, PRSA)
        self.private_key, self.public_key = generate_rsa_keys()
        self.id_elezione = id_elezione

        # Registri interni del SA
        self.eligible_voters: set[str] = set()       # Anagrafica aventi diritto
        self.issued_tokens: set[str] = set()         # Per garantire Unicità [AUTH-1]
        self.pending_challenges: dict[str, str] = {} # Mappa voter_id -> nonce

    # ──────────────────────────────────────────────
    # REGISTRAZIONE ELETTORI (Fase 0 - Setup)
    # ──────────────────────────────────────────────

    def register_eligible_voter(self, voter_id: str) -> None:
        """
        Popola l'anagrafica degli aventi diritto (Es. studenti iscritti).
        Simula il ruolo dell'Ateneo pre-elezione.
        """
        self.eligible_voters.add(voter_id)

    # ──────────────────────────────────────────────
    # AUTENTICAZIONE E PROOF-OF-POSSESSION (Fase 1)
    # ──────────────────────────────────────────────

    def request_challenge(self, voter_id: str) -> str:
        """
        L'elettore richiede di votare. Il SA verifica il diritto ed emette un challenge.
        """
        if voter_id not in self.eligible_voters:
            raise ValueError(f"Accesso negato: {voter_id} non è un avente diritto.")
        
        if voter_id in self.issued_tokens:
            raise ValueError(f"Accesso negato: {voter_id} ha già ottenuto un certificato (Doppio voto bloccato).")

        # Generazione del nonce per il challenge
        nonce = secrets.token_hex(32)
        self.pending_challenges[voter_id] = nonce
        return nonce

    @measure_time("Emissione Certificato Pseudonimo (SA)")
    def verify_and_issue_certificate(
        self, 
        voter_id: str, 
        pu_v: RSAPublicKey, 
        challenge_signature: bytes
    ) -> dict:
        """
        WP2 Sezione 4.2.3: Riceve la chiave effimera (PU_v) e la firma sul nonce.
        Se valida, emette Cp = { PU_v, id_elezione, Sign_PRSA(H(PU_v || id_elezione)) }.
        """
        if voter_id not in self.pending_challenges:
            raise ValueError("Challenge assente o scaduto.")

        nonce = self.pending_challenges.pop(voter_id)

        # Il payload firmato dall'elettore deve corrispondere al nonce fornito
        challenge_payload = serialize({"nonce": nonce})

        # Verifica Proof-of-Possession usando la CHIAVE EFFIMERA PU_v [AUTH-2]
        if not verify_signature(pu_v, challenge_payload, challenge_signature):
            raise ValueError("Firma del challenge non valida. Proof-of-Possession fallito.")

        # L'identità è confermata. Registriamo l'utente per impedire rilasci futuri [UNIQ-1]
        self.issued_tokens.add(voter_id)

        # Costruzione del Certificato Pseudonimo C_p
        pu_v_bytes = pubkey_to_bytes(pu_v).decode('utf-8')
        
        cp_payload = {
            "PU_v": pu_v_bytes,
            "id_elezione": self.id_elezione
        }
        
        # Il SA firma il digest di PU_v e id_elezione usando la propria chiave PR_SA
        cp_payload_bytes = serialize(cp_payload)
        signature = sign(self.private_key, cp_payload_bytes)

        certificato_pseudonimo = {
            "payload": cp_payload,
            "signature": signature.hex()
        }

        return certificato_pseudonimo

    def get_public_key(self) -> RSAPublicKey:
        return self.public_key