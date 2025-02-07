import os
import uuid
import secrets

secret1 = os.urandom(12)

secret2 = uuid.uuid4().hex

secret3 = secrets.token_urlsafe(12)

print(f"SECRETE KEY FROM os LIB:\n {secret1}")
print("")
print(f"SECRETE KEY FROM uuid LIB:\n {secret2}")
print("")
print(f"SECRETE KEY FROM secretes LIB:\n {secret3}")

