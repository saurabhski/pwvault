import os
import time

from crypto import SALT_BYTES, derive_key

def test_derive_key_returns_32_bytes():
    key = derive_key(master_password='password123', salt=bytes(SALT_BYTES))
    assert len(key) == 32

def test_derive_key_returns_bytes():
    key = derive_key(master_password='password123', salt=os.urandom(SALT_BYTES))
    assert bytes(key)

def test_derive_key_is_deterministic():
    salt = os.urandom(SALT_BYTES)
    key1 = derive_key(master_password='password123', salt=salt)
    key2 = derive_key(master_password='password123', salt=salt)
    assert key1 == key2

def test_derive_key_differs_with_different_salt():
    key1 = derive_key(master_password='password123', salt=os.urandom(SALT_BYTES))
    key2 = derive_key(master_password='password123', salt=os.urandom(SALT_BYTES))
    assert key1 != key2 

def test_derive_key_differs_with_different_password():
    salt = os.urandom(SALT_BYTES)
    key1 = derive_key(master_password='pass1', salt=salt)
    key2 = derive_key(master_password='pass2', salt=salt)
    assert key1 != key2

def test_derive_key_handles_non_ascii_password():
    salt = os.urandom(SALT_BYTES)
    key = derive_key(master_password='password🤣ále', salt=salt)
    assert bytes(key)

def test_derive_key_completes_quickly():
    salt = os.urandom(SALT_BYTES)
    start = time.perf_counter()
    derive_key(master_password='password123', salt=salt)
    elapsed = time.perf_counter() - start
    assert elapsed <1.0