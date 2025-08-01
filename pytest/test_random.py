import pkcs11
import os
import hashlib
from time import time
from tqdm import tqdm
from pkcs11 import ObjectClass, Mechanism, Attribute, KeyType

lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')
pin = '1234'

iterations = 100  
randsize = 8196

print("Testing random generation throughput")
t0 = time()
total = 0

with token.open(rw=True, user_pin=pin) as session:
    for _ in tqdm(range(iterations)):
            rnd = session.generate_random(randsize)
            total += len(rnd)

elapsed = time() - t0
rate = total / elapsed

print(f"Generated {total} bytes in {elapsed:.2f}s > {rate:.2f} bytes/s")

