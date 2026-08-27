from typing import Optional

from src.crypto_utils import (
    serialize, 
    hash_sha256_hex, 
    sign, 
    verify_signature, 
    measure_time,
    get_size_in_bytes
)
from src.merkle_tree import MerkleTree
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class PublicUrn:
    """
    Urna Pubblica Ibrida (WP2 Sezione 4.4 - Figura 3).
    Combina un Append-Only Log basato su Hash Chain e un Merkle Tree sui Fingerprint.
    NON CONTIENE MAI IL CIPHERTEXT C_j. Contiene solo K_j e F_j.
    """

    def __init__(self, ae_private_key: RSAPrivateKey, election_params: dict):
        self.chain: list[dict] = []
        self.merkle_tree: Optional[MerkleTree] = None
        self.ae_private_key = ae_private_key
        
        # WP2 Sezione 4.1.3: Blocco di testa dell'urna (Record_0 / Genesi)
        self._create_genesis_block(election_params)

    def _create_genesis_block(self, params: dict) -> None:
        """Crea il Record_0 ancorando i parametri pubblici dell'elezione."""
        payload = {
            "j": 0,
            "params": params,
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }
        payload_bytes = serialize(payload)
        signature = sign(self.ae_private_key, payload_bytes)
        
        record_0 = {
            "payload": payload,
            "signature": signature.hex()
        }
        self.chain.append(record_0)

    @measure_time("Aggiunta Record all'Urna (AE)")
    def add_record(self, j: int, k_j: str, f_j: str) -> None:
        """
        Aggiunge un voto validato alla Hash Chain.
        WP2 Sezione 4.4: Record_j = { j, K_j, F_j, H(Record_{j-1}), Sign_AE(...) }
        """
        # Hash del blocco precedente per garantire l'immutabilità temporale [INT-3]
        prev_record_bytes = serialize(self.chain[-1])
        prev_hash = hash_sha256_hex(prev_record_bytes)

        payload = {
            "j": j,
            "K_j": k_j,
            "F_j": f_j,
            "prev_hash": prev_hash
        }
        
        # L'AE firma il digest di tutto il payload
        payload_bytes = serialize(payload)
        signature = sign(self.ae_private_key, payload_bytes)

        record_j = {
            "payload": payload,
            "signature": signature.hex()
        }
        
        self.chain.append(record_j)
        self.merkle_tree = None  # Invalida l'albero corrente

    def close_urn(self, k_totale: int) -> dict:
        """
        WP2 Sezione 4.5.1: Chiusura e congelamento dell'urna.
        Aggiunge il Record_chiusura alla catena.
        """
        prev_record_bytes = serialize(self.chain[-1])
        prev_hash = hash_sha256_hex(prev_record_bytes)
        merkle_root = self.get_merkle_root_hex() if k_totale > 0 else "EMPTY"

        payload = {
            "j": "CHIUSURA",
            "k_totale": k_totale,
            "merkle_root_finale": merkle_root,
            "prev_hash": prev_hash
        }
        
        payload_bytes = serialize(payload)
        signature = sign(self.ae_private_key, payload_bytes)

        record_chiusura = {
            "payload": payload,
            "signature": signature.hex()
        }
        self.chain.append(record_chiusura)
        return record_chiusura

    # ──────────────────────────────────────────────
    # GESTIONE MERKLE TREE E VERIFICHE
    # ──────────────────────────────────────────────

    def get_merkle_tree(self) -> MerkleTree:
        """Costruisce il Merkle Tree utilizzando ESCLUSIVAMENTE i Fingerprint F_j."""
        if self.merkle_tree is None:
            # Estraiamo i Fingerprint ignorando il Record_0 (Genesi) e la Chiusura (se presente)
            fingerprints = [
                record["payload"]["F_j"].encode('utf-8') 
                for record in self.chain 
                if isinstance(record["payload"]["j"], int) and record["payload"]["j"] > 0
            ]
            if not fingerprints:
                raise ValueError("Nessun voto presente per costruire il Merkle Tree.")
            self.merkle_tree = MerkleTree(fingerprints)
        return self.merkle_tree

    def get_merkle_root_hex(self) -> str:
        return self.get_merkle_tree().root_hex()

    def get_proof(self, j: int) -> list[tuple[str, bytes]]:
        """Restituisce la Merkle Proof per il record con indice j (j parte da 1)."""
        # Poiché l'albero è costruito solo sui voti, l'indice j-1 corrisponde alla foglia corretta
        return self.get_merkle_tree().generate_proof(j - 1)

    @measure_time("Verifica Universale Hash Chain [VER-2]")
    def verify_hash_chain(self, ae_public_key: RSAPublicKey) -> bool:
        """
        Il Verificatore Pubblico controlla:
        1. L'integrità sequenziale degli Hash Pointer (prev_hash).
        2. La validità di tutte le firme dell'AE sui blocchi.
        """
        for i in range(1, len(self.chain)):
            prev_record = self.chain[i - 1]
            curr_record = self.chain[i]
            
            # 1. Verifica Hash Pointer
            expected_prev_hash = hash_sha256_hex(serialize(prev_record))
            if curr_record["payload"]["prev_hash"] != expected_prev_hash:
                print(f"[ERRORE] Hash Pointer rotto al blocco {curr_record['payload']['j']}")
                return False
                
            # 2. Verifica Firma AE
            payload_bytes = serialize(curr_record["payload"])
            signature_bytes = bytes.fromhex(curr_record["signature"])
            if not verify_signature(ae_public_key, payload_bytes, signature_bytes):
                print(f"[ERRORE] Firma non valida al blocco {curr_record['payload']['j']}")
                return False
                
        return True

    def get_urn_size_bytes(self) -> int:
        """Restituisce la dimensione in byte dell'intera Urna Pubblica (Metriche WP4)."""
        return get_size_in_bytes(self.chain)