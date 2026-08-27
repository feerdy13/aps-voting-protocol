from typing import Optional
import datetime

from src.sa_server import AuthServer
from src.public_urn import PublicUrn
from src.ae_server import ElectoralAuthority
from src.verifier import PublicVerifier
from src.voter import Voter
from src.crypto_utils import get_size_in_bytes


class ElectionSimulation:
    """
    Simulazione completa del protocollo di voto elettronico (WP1 e WP2).
    Coordina SA, AE, Urna Pubblica, Elettori e Verificatore.
    """

    def __init__(self, election_id: str, candidates: list[str]):
        if not candidates:
            raise ValueError("L'elezione richiede almeno un candidato.")

        self.election_id = election_id
        self.candidates = candidates
        
        # WP2 4.1.3: Parametri pubblici dell'elezione
        self.election_params = {
            "id_elezione": self.election_id,
            "lista_candidati": self.candidates,
            "t_apertura": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "t_chiusura": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).isoformat()
        }

        # Inizializzazione Attori
        self.auth_server = AuthServer(self.election_id)
        
        # L'AE crea le chiavi RSA, estraiamo subito la sua chiave di firma per l'urna
        # (Per evitare dipendenze circolari l'Urna viene instanziata con PR_AE)
        from src.crypto_utils import generate_rsa_keys
        ae_sign_pr, ae_sign_pu = generate_rsa_keys()
        
        self.public_urn = PublicUrn(ae_private_key=ae_sign_pr, election_params=self.election_params)
        
        self.electoral_authority = ElectoralAuthority(
            sa_public_key=self.auth_server.get_public_key(),
            urn=self.public_urn,
            election_params=self.election_params
        )

        self.public_verifier = PublicVerifier(ae_public_key=ae_sign_pu)

        self.voters: dict[str, Voter] = {}
        
        # Metriche di rete (WP4)
        self.network_metrics = {
            "bytes_tx_certificati_cp": 0,
            "bytes_tx_pacchetti_m": 0,
            "bytes_tx_ricevute_r": 0,
            "bytes_urna_pubblica_finale": 0
        }
        self.doc_finale: Optional[dict] = None

    # ──────────────────────────────────────────────
    # FASE 0 & 1: SETUP E AUTENTICAZIONE
    # ──────────────────────────────────────────────

    def register_voter(self, voter_id: str) -> None:
        """Il SA registra l'anagrafica (simula l'immatricolazione d'Ateneo)."""
        self.auth_server.register_eligible_voter(voter_id)
        self.voters[voter_id] = Voter(voter_id, self.election_id)

    def authenticate_all_voters(self) -> None:
        """Simula la Fase 1: ogni elettore ottiene il suo certificato pseudonimo Cp."""
        for voter_id, voter in self.voters.items():
            voter.authenticate_and_get_certificate(self.auth_server)
            # Raccogliamo la dimensione del certificato (WP4)
            self.network_metrics["bytes_tx_certificati_cp"] += get_size_in_bytes(voter.certificato_pseudonimo)

    # ──────────────────────────────────────────────
    # FASE 2 & 3: VOTO E RICEZIONE
    # ──────────────────────────────────────────────

    def cast_vote(self, voter_id: str, candidate: str) -> bool:
        """
        Simula il processo Encrypt-then-Sign dell'Elettore (Fase 2)
        e la Ricezione/Controlli dell'AE (Fase 3).
        """
        if candidate not in self.candidates:
            raise ValueError(f"Candidato non valido: {candidate}")

        voter = self.voters[voter_id]
        ae_pub_key = self.electoral_authority.get_encryption_public_key()

        # Fase 2: Costruzione pacchetto M
        m_packet = voter.create_ballot_packet(candidate, ae_pub_key)
        self.network_metrics["bytes_tx_pacchetti_m"] += get_size_in_bytes(m_packet)

        # Fase 3: L'AE lo riceve, esegue i controlli ed emette R
        try:
            receipt = self.electoral_authority.receive_ballot(m_packet, voter.pu_v)
            self.network_metrics["bytes_tx_ricevute_r"] += get_size_in_bytes(receipt)
            
            # L'elettore salva la ricevuta e distrugge la chiave effimera [SEC-3]
            voter.store_receipt_and_cleanup(receipt)
            return True
        except ValueError as e:
            print(f"[AE Rifiuto] {e}")
            return False

    def cast_multiple_votes(self, votes_dict: dict[str, str]) -> None:
        """Esegue votazioni di massa a partire da un dizionario {voter_id: candidato}."""
        for voter_id, candidate in votes_dict.items():
            self.cast_vote(voter_id, candidate)

    # ──────────────────────────────────────────────
    # FASE 4: CHIUSURA E SCRUTINIO
    # ──────────────────────────────────────────────

    def close_and_tally(self) -> dict:
        """Chiude le urne ed esegue lo scrutinio Black-Box."""
        self.doc_finale = self.electoral_authority.close_and_tally()
        self.network_metrics["bytes_urna_pubblica_finale"] = self.public_urn.get_urn_size_bytes()
        return self.doc_finale

    # ──────────────────────────────────────────────
    # FASE 5: VERIFICHE (Individuale e Universale)
    # ──────────────────────────────────────────────

    def run_individual_verifications(self) -> dict[str, bool]:
        """Ogni elettore verifica l'inclusione della propria scheda [VER-1]."""
        results = {}
        for voter_id, voter in self.voters.items():
            if voter.ricevuta_r:
                results[voter_id] = voter.verify_individual_inclusion(self.public_urn)
            else:
                results[voter_id] = False
        return results

    def run_universal_verification(self) -> bool:
        """Il Verificatore Pubblico convalida l'elezione [VER-2]."""
        if not self.doc_finale:
            raise ValueError("Scrutinio non ancora eseguito.")
        return self.public_verifier.verify_universal(self.public_urn, self.doc_finale)