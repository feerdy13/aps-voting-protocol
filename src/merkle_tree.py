from src.crypto_utils import hash_sha256, measure_time

class MerkleTree:
    """
    Merkle Tree costruito su SHA-256.
    Nel nostro protocollo (WP2), le foglie sono i Fingerprint Fj.
    """

    def __init__(self, leaves: list[bytes]):
        """
        leaves: lista di dati in bytes (es. i fingerprint Fj serializzati).
        """
        if not leaves:
            raise ValueError("Il Merkle Tree richiede almeno una foglia.")

        self.original_leaves = leaves
        self.levels = self._build(leaves)

    # ──────────────────────────────────────────────
    # COSTRUZIONE DEL MERKLE TREE (Con Metriche WP4)
    # ──────────────────────────────────────────────

    @measure_time("Costruzione Merkle Tree")
    def _build(self, leaves: list[bytes]) -> list[list[bytes]]:
        """
        Costruisce l'albero dal basso verso la radice.
        Misurato con @measure_time per valutare il carico computazionale sull'AE (WP4).
        """
        # Primo livello: le foglie vengono hashate.
        current_level = [hash_sha256(leaf) for leaf in leaves]
        levels = [current_level]

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # Se i nodi sono dispari, l'ultimo viene duplicato (standard Bitcoin)
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                # Ogni nodo padre è hash(left || right)
                next_level.append(hash_sha256(left + right))

            current_level = next_level
            levels.append(current_level)

        return levels

    # ──────────────────────────────────────────────
    # RADICE DEL MERKLE TREE
    # ──────────────────────────────────────────────

    def root(self) -> bytes:
        """Restituisce la radice del Merkle Tree."""
        return self.levels[-1][0]

    def root_hex(self) -> str:
        """Restituisce la radice in formato esadecimale (utile per la stampa)."""
        return self.root().hex()

    # ──────────────────────────────────────────────
    # GENERAZIONE DELLA MERKLE PROOF
    # ──────────────────────────────────────────────

    def generate_proof(self, index: int) -> list[tuple[str, bytes]]:
        """
        Genera la Merkle proof per la verifica individuale [VER-1].
        Ogni elemento è una coppia:
        - ("L", hash): fratello a sinistra
        - ("R", hash): fratello a destra
        """
        if index < 0 or index >= len(self.original_leaves):
            raise IndexError("Indice della foglia non valido.")

        proof = []
        current_index = index

        for level in self.levels[:-1]:
            # Se l'indice è pari, il fratello è a destra ("R")
            if current_index % 2 == 0:
                sibling_index = current_index + 1 if current_index + 1 < len(level) else current_index
                proof.append(("R", level[sibling_index]))
            # Se l'indice è dispari, il fratello è a sinistra ("L")
            else:
                sibling_index = current_index - 1
                proof.append(("L", level[sibling_index]))

            current_index //= 2

        return proof

# ──────────────────────────────────────────────
# VERIFICA DELLA MERKLE PROOF (Con Metriche WP4)
# ──────────────────────────────────────────────

@measure_time("Verifica Individuale (Merkle Proof)")
def verify_proof(leaf: bytes, index: int, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    """
    Verifica che una foglia appartenga a un Merkle Tree con la radice data.
    Misurata con @measure_time per mostrare la latenza lato client [VER-1] nel WP4.
    """
    if index < 0:
        return False

    # Si parte dall'hash della foglia originale
    current_hash = hash_sha256(leaf)

    for direction, sibling in proof:
        if direction == "R":
            current_hash = hash_sha256(current_hash + sibling)
        elif direction == "L":
            current_hash = hash_sha256(sibling + current_hash)
        else:
            return False

    return current_hash == root