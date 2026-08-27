import secrets
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import (
    generate_rsa_keys,
    encrypt_oaep,
    hash_sha256_hex,
    sign,
    serialize,
    measure_time
)
from src.sa_server import AuthServer
from src.public_urn import PublicUrn

class Voter:
    """
    Elettore del sistema di voto elettronico.
    WP2: Crea chiavi effimere, ottiene il C_p dal SA, cifra il voto,
    firma il pacchetto M (Encrypt-then-Sign), verifica la ricevuta R 
    e cancella il materiale effimero per [SEC-3].
    """

    def __init__(self, voter_id: str, id_elezione: str):
        self.voter_id = voter_id
        self.id_elezione = id_elezione
        
        # WP2 4.2.1: Coppia di chiavi RSA effimera (monouso)
        self.pr_v, self.pu_v = generate_rsa_keys()

        # Stato interno dell'elettore
        self.certificato_pseudonimo: Optional[dict] = None
        self.nonce_eta: Optional[str] = None
        self.ciphertext_c: Optional[str] = None
        self.ricevuta_r: Optional[dict] = None

    # ──────────────────────────────────────────────
    # FASE 1: AUTENTICAZIONE ED EMISSIONE C_p
    # ──────────────────────────────────────────────

    @measure_time("Fase 1: Ottenimento Certificato Pseudonimo (Client)")
    def authenticate_and_get_certificate(self, sa: AuthServer) -> None:
        """
        Richiede il challenge, lo firma con PR_v (Proof-of-Possession) 
        e ottiene C_p dal Sistema di Autenticazione.
        """
        # 1. Richiesta challenge
        nonce = sa.request_challenge(self.voter_id)

        # 2. Firma del challenge (Proof-of-Possession su chiave effimera) [AUTH-2]
        challenge_payload = serialize({"nonce": nonce})
        challenge_signature = sign(self.pr_v, challenge_payload)

        # 3. Sottomissione e ricezione di C_p
        self.certificato_pseudonimo = sa.verify_and_issue_certificate(
            self.voter_id,
            self.pu_v,
            challenge_signature
        )

    # ──────────────────────────────────────────────
    # FASE 2: PREPARAZIONE DEL PACCHETTO DI VOTO
    # ──────────────────────────────────────────────

    @measure_time("Fase 2: Preparazione Pacchetto Voto M (Client)")
    def create_ballot_packet(self, voto: str, ae_public_key: RSAPublicKey) -> dict:
        """
        WP2 Sezione 4.2.5: Pacchetto di voto ed Encrypt-then-Sign.
        M = (C, C_p, eta, id_elezione, sigma)
        """
        if not self.certificato_pseudonimo:
            raise ValueError("Impossibile votare: Certificato Pseudonimo mancante.")

        # Cifratura RSA-OAEP del voto in chiaro
        voto_bytes = voto.encode('utf-8')
        c_bytes = encrypt_oaep(ae_public_key, voto_bytes)
        self.ciphertext_c = c_bytes.hex()

        # Generazione del Nonce (eta) a 256 bit
        self.nonce_eta = secrets.token_hex(32)

        # Creazione del payload da firmare
        payload_da_firmare = {
            "C": self.ciphertext_c,
            "C_p": self.certificato_pseudonimo,
            "eta": self.nonce_eta,
            "id_elezione": self.id_elezione
        }

        # Firma effimera sul pacchetto [INT-1]
        sigma = sign(self.pr_v, serialize(payload_da_firmare))

        # Assemblaggio del pacchetto M finale
        m_packet = {
            "C": self.ciphertext_c,
            "C_p": self.certificato_pseudonimo,
            "eta": self.nonce_eta,
            "id_elezione": self.id_elezione,
            "sigma": sigma.hex()
        }
        
        return m_packet

    # ──────────────────────────────────────────────
    # GESTIONE RICEVUTA E CANCELLAZIONE EFFIMERA
    # ──────────────────────────────────────────────

    def store_receipt_and_cleanup(self, receipt: dict) -> None:
        """
        WP2 4.3.4: Cancellazione del materiale effimero.
        Subito dopo aver ricevuto la ricevuta R, l'elettore elimina PR_v.
        Garantisce l'Assenza di Ricevuta Rivelante [SEC-3].
        """
        self.ricevuta_r = receipt
        
        # Eliminazione chiave privata effimera
        self.pr_v = None
        # Eliminare ciphertext e chiavi protegge contro coercizione retroattiva
        # Si mantengono solo i dati necessari per ricalcolare K e F per VER-1

    # ──────────────────────────────────────────────
    # FASE 5: VERIFICA INDIVIDUALE [VER-1]
    # ──────────────────────────────────────────────

    @measure_time("Verifica Individuale (Client) [VER-1]")
    def verify_individual_inclusion(self, urna: PublicUrn) -> bool:
        """
        L'elettore ricalcola K_j e F_j, chiede la Merkle Proof all'urna e
        verifica che il proprio voto sia incluso nella Merkle Root finale.
        """
        if not self.ricevuta_r or not self.ciphertext_c or not self.nonce_eta:
            print(f"[{self.voter_id}] Dati mancanti per la verifica individuale.")
            return False

        # 1. Ricalcolo locale di K e F
        k_locale = hash_sha256_hex(bytes.fromhex(self.ciphertext_c))
        f_locale = hash_sha256_hex((k_locale + self.nonce_eta).encode('utf-8'))

        # 2. Controllo coerenza ricevuta
        if f_locale != self.ricevuta_r["payload"]["F_j"]:
            print(f"[{self.voter_id}] Errore: Il Fingerprint calcolato non coincide con la ricevuta R!")
            return False

        j = self.ricevuta_r["payload"]["j"]

        # 3. Richiesta Merkle Proof dall'Urna Pubblica
        try:
            proof = urna.get_proof(j)
        except IndexError:
            print(f"[{self.voter_id}] Errore: Indice j={j} non trovato nell'urna.")
            return False

        # 4. Recupero la Root Ufficiale (dal record di chiusura)
        record_chiusura = urna.chain[-1]
        if record_chiusura["payload"]["j"] != "CHIUSURA":
            print(f"[{self.voter_id}] Attenzione: Urna non ancora chiusa. Impossibile verificare contro root_finale.")
            return False
            
        root_pubblica = bytes.fromhex(record_chiusura["payload"]["merkle_root_finale"])

        # 5. Verifica della Proof usando la funzione in merkle_tree.py
        from src.merkle_tree import verify_proof
        is_included = verify_proof(f_locale.encode('utf-8'), j - 1, proof, root_pubblica)

        return is_included