import pkcs11
import os
import hashlib
from time import time
from tqdm import tqdm
from pkcs11 import ObjectClass, Mechanism, Attribute

lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')
pin = '1234'
iterations = 50
print("Testing KeyGen")
tot = 0

for i in tqdm(range(iterations)):
    session = token.open(rw=True, user_pin=pin)

    t = time()

    pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048, store=True)

    tot += time() - t   

    session.close()

print(f"keyGen speed: {iterations/tot}")



