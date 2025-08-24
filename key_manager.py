# key_manager.py
import os
from models import db, QuantumKey

# Key size is 1kb (1024 bits), which is 128 bytes.
KEY_SIZE_BYTES = 128

def get_unused_key():
    """Fetches one unused quantum key from the database."""
    key_record = QuantumKey.query.filter_by(is_used=False).first()
    if not key_record:
        # In a real-world application, this would trigger a request for more keys.
        raise Exception("Key bank is empty. No unused keys available.")
    return key_record

def mark_key_as_used(key_record):
    """Marks a given key record as used in the database."""
    key_record.is_used = True
    db.session.commit()

def populate_key_bank_if_empty(count=100):
    """Adds a number of new, randomly generated keys to the DB if it's empty."""
    if QuantumKey.query.count() == 0:
        print(f"Key bank is empty. Populating with {count} new dummy keys...")
        for _ in range(count):
            # This generates cryptographically secure pseudo-random data as a
            # placeholder for your actual quantum keys.
            dummy_key_data = os.urandom(KEY_SIZE_BYTES)
            new_key = QuantumKey(key_data=dummy_key_data)
            db.session.add(new_key)
        db.session.commit()
        print("Key bank populated.")
# in key_manager.py

def get_key_by_id(key_id):
    """Fetches a specific quantum key by its UUID."""
    return QuantumKey.query.get(key_id)