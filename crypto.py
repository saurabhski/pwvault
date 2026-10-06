import argon2.low_level


# Turns a master password into into a key and move entry data between plaintext and authenticated ciphertext

ARGON2_MEMORY_COST = 47104 # KiB (46MiB), OWASP recommended Argon2id minimum
ARGON2_TIME_COST = 1
ARGON2_PARALLELISM = 1
ARGON2_TYPE = argon2.low_level.Type.ID
ARGON2_HASH_LEN = 32 #AES-256 needs 256 bit key
SALT_BYTES = 16
NONCE_BYTES = 12
VAULT_VERSION = 1
VAULT_FILE_MODE = 0o600

def derive_key(master_password: str, salt: bytes) -> bytes:
    password_bytes = master_password.encode("utf-8")
    return argon2.low_level.hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=ARGON2_TYPE,
    )

    
