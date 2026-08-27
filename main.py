import sys
from pathlib import Path
from src.election_simulation import ElectionSimulation

def print_separator() -> None:
    print("-" * 75)

def main() -> None:
    """
    Esegue una simulazione completa del protocollo "Happy Path" (WP1 Sez. 1.7 Completeness).
    Dimostra la correttezza algoritmica in assenza di avversari.
    """
    ELECTION_ID = "ELEZ_RAPPR_STUDENTI_2026"
    candidates = ["Lista Alfa", "Lista Beta", "Lista Gamma"]
    
    votes = {
        "MATR_001": "Lista Alfa",
        "MATR_002": "Lista Beta",
        "MATR_003": "Lista Alfa",
        "MATR_004": "Lista Gamma",
        "MATR_005": "Lista Alfa"
    }

    print_separator()
    print(" === SIMULAZIONE PROTOCOLLO DI VOTO ELETTRONICO (Happy Path) ===")
    print(f" Elezione: {ELECTION_ID}")
    print_separator()

    # 1. SETUP
    print("\n[Setup] Inizializzazione infrastruttura crittografica e chiavi RSA...")
    simulation = ElectionSimulation(ELECTION_ID, candidates)

    # 2. REGISTRAZIONE AVENTI DIRITTO
    print("\n[Fase 0] L'Ateneo comunica le anagrafiche al Sistema di Autenticazione (SA)...")
    for voter_id in votes.keys():
        simulation.register_voter(voter_id)
        print(f"  - Registrato avente diritto: {voter_id}")

    # 3. AUTENTICAZIONE E RILASCIO CERTIFICATI
    print("\n[Fase 1] Autenticazione ed emissione Certificati Pseudonimi (Cp)...")
    simulation.authenticate_all_voters()
    print("  - Tutti gli elettori hanno superato il Proof-of-Possession [AUTH-2].")
    print("  - Il SA ha rilasciato i Cp. Il SA non conosce i voti [SEC-2].")

    # 4. SOTTOMISSIONE VOTI (Fase 2 e Fase 3)
    print("\n[Fasi 2 e 3] Preparazione schede, sottomissione all'AE e ricezione Ricevute (R)...")
    for voter_id, vote in votes.items():
        success = simulation.cast_vote(voter_id, vote)
        if success:
            voter = simulation.voters[voter_id]
            print(f"  - [Elettore {voter_id}] Voto inviato. Ricevuta R ottenuta per j = {voter.ricevuta_r['payload']['j']}")
            print(f"    -> Chiave effimera distrutta per Assenza di Ricevuta [SEC-3]")

    # 5. CHIUSURA E SCRUTINIO
    print("\n[Fase 4] Chiusura formale delle Urne e Scrutinio Black-Box...")
    doc_finale = simulation.close_and_tally()
    
    print("\n=== DOCUMENTO DI SCRUTINIO FINALE ===")
    print(f"  Schede Totali Registrate:  {doc_finale['payload']['k_totale']}")
    print(f"  Schede Conformi:           {doc_finale['payload']['k_conformi']}")
    print(f"  Schede Invalide/Scartate:  {doc_finale['payload']['k_invalide']}")
    print("  Risultati:")
    for candidato, count in doc_finale['payload']['Risultato'].items():
        print(f"    - {candidato}: {count} voti")
    print(f"  Merkle Root Definitiva:    {doc_finale['payload']['Merkle_Root_finale'][:30]}...")
    print(f"  Firma AE sul Documento:    {doc_finale['signature'][:30]}...")
    print("=====================================")

    # 6. VERIFICHE
    print("\n[Fase 5] Esecuzione Verifiche Crittografiche...")
    
    print("\n  >> Verifica Individuale Elettori [VER-1]")
    individual_checks = simulation.run_individual_verifications()
    for voter_id, is_valid in individual_checks.items():
        status = "INCLUSA" if is_valid else "NON TROVATA"
        print(f"    - [Elettore {voter_id}]: Verifica Merkle Proof -> {status}")

    print("\n  >> Verifica Universale Globale [VER-2]")
    universal_valid = simulation.run_universal_verification()
    
    print_separator()
    print("\n[Urna Pubblica] Esplorazione contenuto (Append-Only Log):")
    for record in simulation.public_urn.chain:
        j = record["payload"]["j"]
        if j == 0:
            print(f"  [Blocco 0] Genesi: Parametri ancorati. Hash Prev: {record['payload']['prev_hash'][:15]}...")
        elif j == "CHIUSURA":
            print(f"  [Blocco {j}] Urna Congelata. Merkle Root pubblicata.")
        else:
            k_j = record["payload"]["K_j"]
            f_j = record["payload"]["F_j"]
            print(f"  [Blocco {j}] Commitment (Kj): {k_j[:15]}... | Fingerprint (Fj): {f_j[:15]}...")
            
    print("\n(I voti in chiaro o cifrati NON sono esposti al pubblico [SEC-1])")
    print_separator()
    print(" FINE SIMULAZIONE")

if __name__ == "__main__":
    # Redirezione dell'output su file, utile per la consegna
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "sample_run.txt"

    with output_file.open("w", encoding="utf-8") as file:
        # Salva la vecchia console
        original_stdout = sys.stdout
        
        # Crea una classe per scrivere sia a video che sul file contemporaneamente
        class DualLogger:
            def __init__(self, console, file):
                self.console = console
                self.file = file
            def write(self, message):
                self.console.write(message)
                self.file.write(message)
            def flush(self):
                self.console.flush()
                self.file.flush()

        sys.stdout = DualLogger(original_stdout, file)

        try:
            main()
        finally:
            sys.stdout = original_stdout