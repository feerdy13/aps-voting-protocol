from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import verify_signature, serialize, measure_time
from src.public_urn import PublicUrn

class PublicVerifier:
    """
    Verificatore Pubblico (WP1 e WP2 Sezione 5.2).
    Osservatore passivo indipendente che convalida l'esito delle elezioni
    partendo esclusivamente dai dati pubblicati, senza decifrare i voti.
    """

    def __init__(self, ae_public_key: RSAPublicKey):
        self.ae_public_key = ae_public_key

    @measure_time("Verifica Universale Globale [VER-2]")
    def verify_universal(self, urn: PublicUrn, doc_finale: dict) -> bool:
        """
        Esegue i controlli descritti nella Sezione 5.2 del WP2.
        Restituisce True se l'elezione è matematicamente valida e non manomessa.
        """
        print("\n[Verificatore] Avvio Verifica Universale [VER-2]...")

        # 1. Integrità sequenziale della Hash Chain e validità delle firme AE sui blocchi
        if not urn.verify_hash_chain(self.ae_public_key):
            print("[ERRORE] La Hash Chain dell'Urna Pubblica risulta corrotta o manomessa.")
            return False
        print("  - [OK] Hash Chain integra e firme sui blocchi valide.")

        # 2. Autenticità del Documento di Scrutinio Finale
        if not self._verify_final_document_signature(doc_finale):
            print("[ERRORE] La firma sul Documento di Scrutinio Finale non è valida.")
            return False
        print("  - [OK] Firma sul Documento Finale autentica.")

        # 3. Consistenza della Merkle Root
        if not self._verify_merkle_root_consistency(urn, doc_finale):
            print("[ERRORE] La Merkle Root del Documento Finale non coincide con quella dell'Urna.")
            return False
        print("  - [OK] Merkle Root consistente tra Urna e Documento Finale.")

        # 4. Coerenza Numerica
        if not self._verify_numerical_consistency(urn, doc_finale):
            print("[ERRORE] Incoerenza nei contatori delle schede.")
            return False
        print("  - [OK] Equazione di coerenza numerica verificata.")

        print("[Verificatore] Verifica Universale completata con SUCCESSO.")
        return True

    # ──────────────────────────────────────────────
    # FUNZIONI DI CONTROLLO INTERNE
    # ──────────────────────────────────────────────

    def _verify_final_document_signature(self, doc_finale: dict) -> bool:
        """Controlla la firma dell'AE sul payload del documento finale."""
        try:
            payload = doc_finale["payload"]
            signature = bytes.fromhex(doc_finale["signature"])
            payload_bytes = serialize(payload)
            
            return verify_signature(self.ae_public_key, payload_bytes, signature)
        except (KeyError, ValueError):
            return False

    def _verify_merkle_root_consistency(self, urn: PublicUrn, doc_finale: dict) -> bool:
        """
        Ricalcola la Merkle Root dai Fingerprint (F_j) presenti nell'urna
        e la confronta con quella dichiarata nel Documento Finale.
        """
        try:
            # Se l'urna ha solo Genesi e Chiusura, i voti sono 0
            if doc_finale["payload"]["k_totale"] == 0:
                return doc_finale["payload"]["Merkle_Root_finale"] == "EMPTY"
            
            recalculated_root = urn.get_merkle_root_hex()
            declared_root = doc_finale["payload"]["Merkle_Root_finale"]
            
            return recalculated_root == declared_root
        except Exception:
            return False

    def _verify_numerical_consistency(self, urn: PublicUrn, doc_finale: dict) -> bool:
        """
        WP2 Sez 5.2: Controlla l'equazione k_conformi + k_invalide = k_totale.
        Controlla inoltre che k_totale corrisponda al numero di record nell'urna
        (escludendo Genesi e Chiusura).
        """
        try:
            k_totale = doc_finale["payload"]["k_totale"]
            k_conformi = doc_finale["payload"]["k_conformi"]
            k_invalide = doc_finale["payload"]["k_invalide"]
            
            # 1. Equazione interna
            if k_conformi + k_invalide != k_totale:
                print(f"    -> [Dettaglio] {k_conformi} + {k_invalide} != {k_totale}")
                return False
                
            # 2. Corrispondenza con l'urna reale
            # L'urna contiene: Record_0 (Genesi) + N record voti + Record_chiusura
            # Quindi i voti reali = len(chain) - 2
            voti_reali = len(urn.chain) - 2
            if k_totale != voti_reali:
                print(f"    -> [Dettaglio] k_totale dichiarato ({k_totale}) diverso da record reali ({voti_reali})")
                return False
                
            return True
        except KeyError:
            return False