from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import (
    generate_rsa_keys,
    decrypt_oaep,
    hash_sha256_hex,
    sign,
    verify_signature,
    serialize,
    measure_time
)
from src.public_urn import PublicUrn

class ElectoralAuthority:
    """
    Autorità Elettorale (AE).
    WP2 Sezione 4.3: Riceve i pacchetti di voto (Encrypt-then-Sign), 
    esegue i controlli sequenziali, emette la Ricevuta R, archivia privatamente 
    il Ciphertext e pubblica K_j e F_j nell'Urna Pubblica (Append-Only Log).
    """

    def __init__(self, sa_public_key: RSAPublicKey, urn: PublicUrn, election_params: dict):
        # Coppia per cifrare/decifrare le schede (PU_ele, PR_ele)
        self.enc_private_key, self.enc_public_key = generate_rsa_keys()
        # La chiave di firma (PU_AE, PR_AE) è gestita dalla PublicUrn
        
        self.sa_public_key = sa_public_key
        self.urn = urn
        self.params = election_params
        
        # WP2 4.3.1: Registri interni per Unicità e Anti-replay
        self.registro_effimeri_ae: set[str] = set()
        self.registro_nonce_ae: set[str] = set()
        
        # WP2 4.3.3: Archivio Interno Privato AE (C_j, Cp, eta)
        self.archivio_privato: dict[int, dict] = {}
        
        self.is_closed = False
        self.indice_progressivo = 1  # j parte da 1 (lo 0 è il Genesi)

    def get_encryption_public_key(self) -> RSAPublicKey:
        return self.enc_public_key

    # ──────────────────────────────────────────────
    # FASE 3: RICEZIONE, CONTROLLI E RICEVUTA
    # ──────────────────────────────────────────────

    @measure_time("Elaborazione Scheda e Rilascio Ricevuta (AE)")
    def receive_ballot(self, m_packet: dict, pu_v: RSAPublicKey) -> dict:
        """
        WP2 Sezione 4.3.1: L'AE riceve il pacchetto M ed esegue i 5 controlli sequenziali.
        M = { "C": ciphertext, "C_p": cert_pseudonimo, "eta": nonce, 
              "id_elezione": id, "sigma": firma_effimera }
        """
        if self.is_closed:
            raise ValueError("Urne chiuse. Sottomissione rifiutata.")

        # Estrazione campi
        c_hex = m_packet["C"]
        c_p = m_packet["C_p"]
        eta = m_packet["eta"]
        id_elezione = m_packet["id_elezione"]
        sigma = m_packet["sigma"]

        # 1. Finestra temporale (gestita dalla variabile is_closed)

        # 2. Verifica Autorizzazione (Firma del SA su C_p)
        cp_payload_bytes = serialize(c_p["payload"])
        cp_signature_bytes = bytes.fromhex(c_p["signature"])
        if not verify_signature(self.sa_public_key, cp_payload_bytes, cp_signature_bytes):
            raise ValueError("[Controllo 2 Fallito] Certificato Pseudonimo non valido.")

        # 3. Unicità (PU_v non usata) [UNIQ-1]
        pu_v_pem = c_p["payload"]["PU_v"]
        if pu_v_pem in self.registro_effimeri_ae:
            raise ValueError("[Controllo 3 Fallito] Doppio voto rilevato (PU_v già usata).")

        # 4. Anti-replay (Nonce non usato) [UNIQ-2]
        if eta in self.registro_nonce_ae:
            raise ValueError("[Controllo 4 Fallito] Replay rilevato (Nonce già usato).")

        # 5. Verifica Integrità (Firma effimera sigma sul pacchetto) [INT-1]
        # Il digest firmato è Hash(C || C_p || eta || id_elezione) come da WP2 4.2.5
        payload_to_verify = {
            "C": c_hex,
            "C_p": c_p,
            "eta": eta,
            "id_elezione": id_elezione
        }
        if not verify_signature(pu_v, serialize(payload_to_verify), bytes.fromhex(sigma)):
            raise ValueError("[Controllo 5 Fallito] Firma effimera del pacchetto non valida.")

        # --- SE TUTTI I CONTROLLI PASSANO ---
        
        # Aggiornamento registri
        self.registro_effimeri_ae.add(pu_v_pem)
        self.registro_nonce_ae.add(eta)
        j = self.indice_progressivo
        self.indice_progressivo += 1

        # Calcolo Commitment K_j e Fingerprint F_j
        k_j = hash_sha256_hex(bytes.fromhex(c_hex))
        f_j = hash_sha256_hex((k_j + eta).encode('utf-8'))

        # WP2 4.3.3: Salvataggio nell'archivio PRIVATO (C_j non va nell'urna)
        self.archivio_privato[j] = {
            "C_j": bytes.fromhex(c_hex),
            "K_j": k_j
        }

        # Registrazione nell'Urna PUBBLICA (solo K_j e F_j)
        self.urn.add_record(j, k_j, f_j)

        # Generazione della Ricevuta R firmata dall'AE
        r_payload = {
            "K_j": k_j,
            "F_j": f_j,
            "j": j,
            "id_elezione": id_elezione
        }
        r_bytes = serialize(r_payload)
        r_signature = sign(self.urn.ae_private_key, r_bytes)

        receipt = {
            "payload": r_payload,
            "signature": r_signature.hex()
        }
        return receipt

    # ──────────────────────────────────────────────
    # FASE 4: CHIUSURA E SCRUTINIO BLACK-BOX
    # ──────────────────────────────────────────────

    @measure_time("Chiusura e Scrutinio Voti (AE)")
    def close_and_tally(self) -> dict:
        """
        WP2 Sezione 4.5: Chiude le urne, decifra le schede, scarta quelle malformate,
        calcola i risultati e produce il Doc_finale.
        """
        self.is_closed = True
        k_totale = len(self.archivio_privato)
        
        # 1. Congela l'urna
        self.urn.close_urn(k_totale)

        # Inizializza conteggi
        k_conformi = 0
        k_invalide = 0
        risultati = {candidato: 0 for candidato in self.params["lista_candidati"]}
        
        # 2. Decifratura e Validazione Conformità [INT-2]
        for j, record_privato in self.archivio_privato.items():
            try:
                # Usa la chiave PR_ele "offline" per decifrare
                voto_bytes = decrypt_oaep(self.enc_private_key, record_privato["C_j"])
                voto_str = voto_bytes.decode('utf-8')
                
                if voto_str in risultati:
                    risultati[voto_str] += 1
                    k_conformi += 1
                else:
                    # Voto decifrato ma fuori range (OUT_OF_RANGE)
                    k_invalide += 1
                    self._mark_invalid(j, record_privato["K_j"], "OUT_OF_RANGE")
                    
            except Exception:
                # Errore di decifratura (es. padding errato, MALFORMED_PADDING)
                k_invalide += 1
                self._mark_invalid(j, record_privato["K_j"], "DECRYPT_FAILED")

        # 3. Documento Finale di Scrutinio
        merkle_root = self.urn.get_merkle_root_hex() if k_totale > 0 else "EMPTY"
        
        doc_payload = {
            "Risultato": risultati,
            "k_totale": k_totale,
            "k_conformi": k_conformi,
            "k_invalide": k_invalide,
            "Merkle_Root_finale": merkle_root
        }
        
        doc_bytes = serialize(doc_payload)
        doc_signature = sign(self.urn.ae_private_key, doc_bytes)

        return {
            "payload": doc_payload,
            "signature": doc_signature.hex()
        }

    def _mark_invalid(self, j: int, k_j: str, motivo: str):
        """Simula la pubblicazione di un record Invalid_j nell'urna."""
        print(f"[AE SCRUTINIO] Record Invalid_j generato: Voto {j} scartato per {motivo}")