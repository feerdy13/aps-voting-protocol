# Progetto di Voto Elettronico Sicuro (E-Voting)

Questo progetto implementa un protocollo di voto elettronico crittograficamente sicuro, sviluppato in Python. L'architettura è stata progettata per garantire anonimato, integrità del voto, verificabilità universale e resilienza contro avversari di rete ed elettori disonesti, in stretta aderenza alle specifiche di progetto (WP1, WP2, WP3, WP4).

---

## 🏛️ Attori del Sistema (WP1 e WP2)

Il protocollo si basa sull'interazione di cinque entità principali, implementate in moduli separati:
*   **Sistema di Autenticazione (SA):** Gestisce le anagrafiche e rilascia i Certificati Pseudonimi ($C_p$) dopo aver verificato il Proof-of-Possession delle chiavi effimere dell'elettore. Garantisce lo pseudo-anonimato.
*   **Autorità Elettorale (AE):** Riceve i pacchetti di voto, esegue i controlli di sicurezza (anti-replay, unicità, validità), archivia segretamente il Ciphertext ed emette la Ricevuta per l'elettore. A fine elezione esegue lo scrutinio *black-box*.
*   **Urna Pubblica:** Un registro pubblico append-only ibrido. Utilizza una **Hash Chain** per garantire l'immutabilità temporale dei record e un **Merkle Tree** per consentire prove di inclusione efficienti. Non espone mai i voti cifrati.
*   **Elettore:** Compone il pacchetto di voto applicando il paradigma *Encrypt-then-Sign*, calcola i propri parametri per la verifica e distrugge il materiale crittografico effimero per garantire l'Assenza di Ricevuta.
*   **Verificatore Pubblico:** Un'entità terza e indipendente che convalida l'integrità matematica dell'elezione (Hash Chain, Merkle Root e Coerenza Numerica) a urne chiuse.

---

## 🛡️ Modello di Minaccia e Sicurezza (WP3)

Il sistema è stato testato contro i principali scenari di attacco:
*   **Man-in-the-Middle (Tampering in transito):** Bloccato dalla firma effimera dell'elettore sul pacchetto.
*   **Replay Attack:** Prevenuto tramite l'uso di nonce a 256-bit memorizzati nei registri dell'AE.
*   **Elettore Disonesto (Doppio Voto):** Bloccato dal registro delle chiavi effimere e dal controllo stringente sull'emissione dei Certificati Pseudonimi.
*   **Voti Malformati / Fuori Range:** Inseriti nell'urna ma intercettati e invalidati durante la fase di decifratura e scrutinio.

---

## ⏱️ Analisi delle Prestazioni e Metriche (WP4)

Il modulo di benchmark valuta l'efficienza computazionale del sistema e l'occupazione di memoria in base ai requisiti del **WP4**:
*   **Costo Computazionale:** Misurazione millimetrica (tramite decoratori ad alte prestazioni) di tutte le primitive crittografiche (RSA-OAEP, RSA-PSS, SHA-256) e della costruzione dei Merkle Tree.
*   **Scalabilità (Stress Test):** Test di carico avanzato sull'Urna Pubblica simulando uno **scenario universitario con 28.000 schede**, dimostrando la scalabilità logaritmica della Hash Chain e del Merkle Tree.
*   **Analisi dei Payload di Rete:** Monitoraggio in byte della dimensione dei certificati $C_p$, dei pacchetti di voto $M$, delle ricevute $R$ e del Bulletin Board finale.

---

## 📁 Struttura del Progetto

Il progetto è suddiviso tra file eseguibili (nella root) e moduli logici (nella cartella `src/`).

### 📄 Root del Progetto (Script Eseguibili)
*   `main.py`: Esegue lo scenario "Happy Path" (simulazione completa senza avversari).
*   `adversary_tests.py`: Esegue la suite di test per validare la resilienza al Modello di Minaccia (WP3).
*   `benchmark.py`: Calcola i tempi di esecuzione, le dimensioni dei payload e simula lo stress test (WP4).
*   `requirements.txt`: Elenca le librerie di terze parti necessarie all'esecuzione (es. `cryptography`).

### 📦 Cartella `src/` (Codice Sorgente)
*   `src/__init__.py`: File di inizializzazione per definire la cartella come pacchetto Python.
*   `src/crypto_utils.py`: Primitive crittografiche (RSA-OAEP, RSA-PSS, SHA-256) e motore per le metriche.
*   `src/merkle_tree.py`: Struttura dati ad albero per le Merkle Proof e la verifica di inclusione.
*   `src/sa_server.py`: Logica del Sistema di Autenticazione (Fase 1).
*   `src/ae_server.py`: Logica dell'Autorità Elettorale (Fasi 3 e 4).
*   `src/public_urn.py`: Urna Pubblica append-only implementata tramite Hash Chain.
*   `src/voter.py`: Entità Elettore (Fasi 2 e 5) e gestione del ciclo di vita delle chiavi effimere.
*   `src/verifier.py`: Osservatore indipendente per la Validazione Universale.
*   `src/election_simulation.py`: Orchestratore che collega tutti gli attori per le simulazioni.

### 📂 Cartella `outputs/` (Generata Automaticamente)
*   `outputs/sample_run.txt`: Log testuale dell'esecuzione di `main.py`.
*   `outputs/benchmark_tempi.csv`: Tabella esportabile con i tempi medi (ms) di tutte le operazioni.
*   `outputs/benchmark_rete.txt`: Report analitico delle dimensioni in byte dei pacchetti.

---

## 🚀 Come Eseguire il Progetto

### 1. Installazione delle Dipendenze
Assicurarsi di avere Python 3 installato e installare la libreria crittografica richiesta:
```bash
pip install -r requirements.txt