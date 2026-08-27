import hashlib
import json
import time
import sys
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization


# ──────────────────────────────────────────────
# STRUMENTI DI MISURAZIONE (WP4)
# ──────────────────────────────────────────────

# Dizionario globale per salvare i tempi di esecuzione per il benchmark (WP4)
performance_metrics: dict[str, list[float]] = {}

def measure_time(func_name: str) -> Callable:
    """
    Decoratore per misurare il tempo di esecuzione di una funzione.
    Aggiunge il tempo (in millisecondi) alla lista in performance_metrics.
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            elapsed_ms = (end_time - start_time) * 1000
            
            if func_name not in performance_metrics:
                performance_metrics[func_name] = []
            performance_metrics[func_name].append(elapsed_ms)
            
            return result
        return wrapper
    return decorator

def get_size_in_bytes(data: Any) -> int:
    """
    Calcola la dimensione in byte di una struttura dati.
    Fondamentale per misurare il payload di rete (WP4).
    """
    if isinstance(data, bytes):
        return len(data)
    elif isinstance(data, str):
        return len(data.encode('utf-8'))
    elif isinstance(data, dict) or isinstance(data, list):
        return len(json.dumps(data, sort_keys=True).encode('utf-8'))
    else:
        return sys.getsizeof(data)


# ──────────────────────────────────────────────
# GENERAZIONE CHIAVI RSA
# ──────────────────────────────────────────────

@measure_time("Generazione Chiavi RSA")
def generate_rsa_keys() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Genera una coppia di chiavi RSA a 2048 bit."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ──────────────────────────────────────────────
# CIFRATURA / DECIFRATURA RSA-OAEP
# ──────────────────────────────────────────────

@measure_time("Cifratura RSA-OAEP")
def encrypt_oaep(public_key: RSAPublicKey, message: bytes) -> bytes:
    """Cifra un messaggio con RSA-OAEP usando SHA-256."""
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

@measure_time("Decifratura RSA-OAEP")
def decrypt_oaep(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decifra un ciphertext RSA-OAEP."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ──────────────────────────────────────────────
# FIRMA DIGITALE / VERIFICA
# ──────────────────────────────────────────────

@measure_time("Firma RSA-PSS")
def sign(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Firma un messaggio con RSA-PSS e SHA-256."""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

@measure_time("Verifica Firma RSA-PSS")
def verify_signature(public_key: RSAPublicKey, message: bytes, signature_bytes: bytes) -> bool:
    """Verifica la firma di un messaggio. Restituisce True se valida."""
    try:
        public_key.verify(
            signature_bytes,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────
# HASH SHA-256 E SERIALIZZAZIONE
# ──────────────────────────────────────────────

def hash_sha256(data: bytes) -> bytes:
    """Calcola SHA-256 di un dato in bytes."""
    return hashlib.sha256(data).digest()

def hash_sha256_hex(data: bytes) -> str:
    """Calcola SHA-256 e restituisce la stringa esadecimale."""
    return hashlib.sha256(data).hexdigest()

def serialize(data: dict) -> bytes:
    """
    Serializza un dizionario in bytes JSON ordinato.
    Fondamentale per il paradigma Hash-and-Sign su dizionari Python.
    """
    return json.dumps(data, sort_keys=True, default=str).encode("utf-8")

def pubkey_to_bytes(public_key: RSAPublicKey) -> bytes:
    """Serializza una chiave pubblica RSA in formato PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )