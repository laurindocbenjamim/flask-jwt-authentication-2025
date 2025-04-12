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

data = {
            "type_of_user": "122344",
            "is_administrator": "Esmolados Nao",
            "is_ceo_user": "Mortos em combate em 12344",
        }
dam={}
for key, value in data.items():
    dam[key]=value
    print(key + '-- '+value)

print(dam)


