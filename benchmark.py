import csv
import statistics
import secrets
from pathlib import Path

from src.election_simulation import ElectionSimulation
from src.crypto_utils import performance_metrics, hash_sha256_hex
from src.public_urn import PublicUrn

OUTPUT_DIR = Path("outputs")
CSV_PATH = OUTPUT_DIR / "benchmark_tempi.csv"
METRICS_PATH = OUTPUT_DIR / "benchmark_rete.txt"

def run_standard_simulation(num_voters: int = 50):
    """
    Esegue un'elezione completa usando il nostro orchestratore.
    I decoratori @measure_time raccoglieranno automaticamente i tempi di ogni funzione.
    """
    print(f"\n[Benchmark] Esecuzione elezione simulata con {num_voters} elettori...")
    sim = ElectionSimulation(election_id="ELEZ_2026_TEST", candidates=["Lista 1", "Lista 2"])
    
    # 1. Registrazione
    voter_ids = [f"MATR_{i:04d}" for i in range(num_voters)]
    for v_id in voter_ids:
        sim.register_voter(v_id)
        
    # 2. Autenticazione (Fase 1)
    sim.authenticate_all_voters()
    
    # 3. Voto (Fasi 2 e 3)
    # Metà vota Lista 1, metà Lista 2
    votes_dict = {v_id: ("Lista 1" if i % 2 == 0 else "Lista 2") for i, v_id in enumerate(voter_ids)}
    sim.cast_multiple_votes(votes_dict)
    
    # 4. Scrutinio (Fase 4)
    sim.close_and_tally()
    
    # 5. Verifiche (Fase 5)
    sim.run_individual_verifications()
    sim.run_universal_verification()
    
    return sim.network_metrics

def run_urna_stress_test(num_records: int = 28000):
    """
    Simula uno Scenario Universitario popolando l'Urna Pubblica (Hash Chain e Merkle Tree)
    con 28.000 record per dimostrare che le nostre strutture dati scalano perfettamente.
    (Non facciamo 28k cifrature RSA per non bloccare il PC per minuti, testiamo l'infrastruttura).
    """
    print(f"[Benchmark] Avvio Stress Test Urna Pubblica con {num_records} record (Scenario Universitario)...")
    
    # Mocking per l'Urna
    from src.crypto_utils import generate_rsa_keys
    _, ae_sign_pu = generate_rsa_keys()
    urna = PublicUrn(ae_private_key=_, election_params={"test": True})
    
    # Popolamento massivo
    for i in range(1, num_records + 1):
        mock_k = hash_sha256_hex(secrets.token_bytes(32))
        mock_f = hash_sha256_hex((mock_k + secrets.token_hex(32)).encode('utf-8'))
        urna.add_record(j=i, k_j=mock_k, f_j=mock_f)
    
    # Costruzione massiva del Merkle Tree (verrà misurata dal decoratore)
    urna.get_merkle_tree()
    print("  -> Stress test completato.")

def save_and_print_time_metrics():
    """Elabora il dizionario globale performance_metrics e lo salva in CSV."""
    results = []
    
    print("\n" + "="*85)
    print(f"{'OPERAZIONE CRITTOGRAFICA (WP4)':<45} | {'CHIAMATE':<8} | {'MEDIA (ms)':<10} | {'DEV STD (ms)':<10}")
    print("-" * 85)
    
    for operation, times in performance_metrics.items():
        count = len(times)
        mean_ms = statistics.mean(times)
        std_ms = statistics.stdev(times) if count > 1 else 0.0
        
        results.append({
            "operazione": operation,
            "chiamate": count,
            "media_ms": round(mean_ms, 4),
            "std_ms": round(std_ms, 4)
        })
        
        print(f"{operation:<45} | {count:<8} | {mean_ms:>10.4f} | {std_ms:>10.4f}")
        
    print("="*85)

    # Salvataggio CSV
    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(CSV_PATH, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["operazione", "chiamate", "media_ms", "std_ms"])
        writer.writeheader()
        writer.writerows(results)
        
def save_and_print_network_metrics(net_metrics: dict):
    """Stampa le dimensioni in byte calcolate durante la simulazione."""
    print("\n" + "="*60)
    print(f"{'METRICHE DI RETE E ARCHIVIAZIONE (WP4)':<45} | {'BYTES'}")
    print("-" * 60)
    
    with open(METRICS_PATH, mode='w', encoding='utf-8') as f:
        f.write("METRICHE DI RETE E ARCHIVIAZIONE (WP4)\n")
        f.write("-" * 60 + "\n")
        for key, value in net_metrics.items():
            formatted_key = key.replace("_", " ").title()
            print(f"{formatted_key:<45} | {value} B")
            f.write(f"{formatted_key:<45} | {value} B\n")
    print("="*60)

def main():
    print("Inizializzazione Benchmark WP4...")
    
    # 1. Esecuzione elezione standard (popola i dati RSA/Firme/ecc)
    net_metrics = run_standard_simulation(num_voters=50)
    
    # 2. Stress Test dell'Urna (popola i dati per alberi giganti)
    run_urna_stress_test(num_records=28000)
    
    # 3. Elaborazione e Stampa Risultati
    save_and_print_time_metrics()
    save_and_print_network_metrics(net_metrics)
    
    print(f"\n[OK] Risultati salvati in '{OUTPUT_DIR}/'.")

if __name__ == "__main__":
    main()