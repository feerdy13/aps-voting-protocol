from src.sa_server import AuthServer
from src.public_urn import PublicUrn
from src.ae_server import ElectoralAuthority
from src.voter import Voter
from src.crypto_utils import generate_rsa_keys, sign, serialize

# Parametri di test globali
ELECTION_ID = "ELEZ_TEST_WP3"
CANDIDATES = ["Lista A", "Lista B"]

def expect_rejection(test_name: str, operation) -> None:
    """Esegue una funzione aspettandosi che fallisca con ValueError."""
    try:
        operation()
    except ValueError as e:
        print(f"[OK] {test_name}: Bloccato con successo -> {e}")
        return
    raise AssertionError(f"[FALLITO] {test_name}: L'attacco è passato inosservato!")

def setup_environment():
    """Crea un ambiente pulito per ogni test."""
    sa = AuthServer(ELECTION_ID)
    _, ae_pu_sign = generate_rsa_keys()
    urn = PublicUrn(ae_private_key=_, election_params={"id": ELECTION_ID})
    ae = ElectoralAuthority(sa.get_public_key(), urn, {"lista_candidati": CANDIDATES})
    return sa, urn, ae

# ──────────────────────────────────────────────
# TEST WP3: FALSARIO E CONTROLLO ACCESSI [AUTH]
# ──────────────────────────────────────────────

def test_invalid_proof_of_possession():
    """WP3 (Falsario): Firma il challenge con una chiave privata sbagliata."""
    sa, _, _ = setup_environment()
    voter = Voter("MATR_001", ELECTION_ID)
    sa.register_eligible_voter(voter.voter_id)

    nonce = sa.request_challenge(voter.voter_id)
    
    # L'attaccante usa una chiave diversa da PU_v per firmare
    fake_pr, _ = generate_rsa_keys()
    fake_signature = sign(fake_pr, serialize({"nonce": nonce}))

    expect_rejection(
        "Falsario - Proof of Possession Invalida [AUTH-2]",
        lambda: sa.verify_and_issue_certificate(voter.voter_id, voter.pu_v, fake_signature)
    )

def test_double_certificate_request():
    """WP3 (Elettore Disonesto): Richiede due certificati pseudonimi."""
    sa, _, _ = setup_environment()
    voter = Voter("MATR_002", ELECTION_ID)
    sa.register_eligible_voter(voter.voter_id)

    # Prima richiesta (Successo)
    voter.authenticate_and_get_certificate(sa)

    # Seconda richiesta (Deve fallire)
    expect_rejection(
        "Elettore Disonesto - Doppia Richiesta Certificato [AUTH-1]",
        lambda: sa.request_challenge(voter.voter_id)
    )

# ──────────────────────────────────────────────
# TEST WP3: AVVERSARIO DI RETE E DOPPIO VOTO
# ──────────────────────────────────────────────

def test_tampering_in_transit():
    """WP3 (Man-in-the-Middle): Modifica il Ciphertext in transito."""
    sa, _, ae = setup_environment()
    voter = Voter("MATR_003", ELECTION_ID)
    sa.register_eligible_voter(voter.voter_id)
    voter.authenticate_and_get_certificate(sa)

    m_packet = voter.create_ballot_packet("Lista A", ae.get_encryption_public_key())
    
    # L'avversario intercetta e modifica un byte del Ciphertext (hex)
    fake_c = m_packet["C"][:-2] + "ff"
    m_packet["C"] = fake_c

    expect_rejection(
        "Man-in-the-Middle - Tampering in Transito [INT-1]",
        lambda: ae.receive_ballot(m_packet, voter.pu_v)
    )

def test_double_voting():
    """WP3 (Elettore Disonesto): Invia due voti con lo stesso certificato Cp."""
    sa, _, ae = setup_environment()
    voter = Voter("MATR_004", ELECTION_ID)
    sa.register_eligible_voter(voter.voter_id)
    voter.authenticate_and_get_certificate(sa)

    # Primo voto (Successo)
    m_packet_1 = voter.create_ballot_packet("Lista A", ae.get_encryption_public_key())
    ae.receive_ballot(m_packet_1, voter.pu_v)

    # Secondo voto con preferenza diversa ma stesso C_p (Deve fallire per Controllo 3)
    m_packet_2 = voter.create_ballot_packet("Lista B", ae.get_encryption_public_key())
    
    expect_rejection(
        "Elettore Disonesto - Doppio Voto con stesso Cp [UNIQ-1]",
        lambda: ae.receive_ballot(m_packet_2, voter.pu_v)
    )

def test_replay_attack():
    """WP3 (Man-in-the-Middle): Invia due volte l'ESATTO stesso pacchetto M."""
    sa, _, ae = setup_environment()
    voter = Voter("MATR_005", ELECTION_ID)
    sa.register_eligible_voter(voter.voter_id)
    voter.authenticate_and_get_certificate(sa)

    m_packet = voter.create_ballot_packet("Lista A", ae.get_encryption_public_key())
    
    # Primo invio
    ae.receive_ballot(m_packet, voter.pu_v)
    
    # L'avversario ritrasmette il pacchetto identico
    expect_rejection(
        "Man-in-the-Middle - Replay Attack [UNIQ-2]",
        lambda: ae.receive_ballot(m_packet, voter.pu_v)
    )

# ──────────────────────────────────────────────
# TEST WP3: SCRUTINIO E VOTI MALFORMATI
# ──────────────────────────────────────────────

def test_out_of_range_vote():
    """WP3 (Elettore Disonesto): Vota per un candidato inesistente."""
    sa, urn, ae = setup_environment()
    voter = Voter("MATR_006", ELECTION_ID)
    sa.register_eligible_voter(voter.voter_id)
    voter.authenticate_and_get_certificate(sa)

    # Il voto è formalmente corretto crittograficamente, ma il candidato non esiste
    m_packet = voter.create_ballot_packet("HACKER", ae.get_encryption_public_key())
    
    # L'AE accetta il pacchetto (entra nell'urna) perché la firma è valida
    ae.receive_ballot(m_packet, voter.pu_v)
    print("[OK] Elettore Disonesto - Voto Fuori Range inserito nell'urna (come previsto).")

    # In fase di scrutinio, il voto deve essere scartato
    doc_finale = ae.close_and_tally()
    
    assert doc_finale["payload"]["k_invalide"] == 1, "Il voto invalido non è stato conteggiato come tale!"
    assert doc_finale["payload"]["k_conformi"] == 0, "Il voto invalido è stato considerato conforme!"
    print("[OK] Autorità Elettorale - Voto Fuori Range correttamente scartato durante lo scrutinio [INT-2].")

def main():
    print("="*70)
    print(" ESECUZIONE TEST DI RESILIENZA AL MODELLO DI MINACCIA (WP3)")
    print("="*70 + "\n")
    
    test_invalid_proof_of_possession()
    test_double_certificate_request()
    test_tampering_in_transit()
    test_double_voting()
    test_replay_attack()
    test_out_of_range_vote()
    
    print("\n" + "="*70)
    print(" TUTTI I TEST PASSATI CON SUCCESSO. IL SISTEMA È RESILIENTE.")
    print("="*70)

if __name__ == "__main__":
    main()