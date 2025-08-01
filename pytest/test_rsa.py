import pkcs11
import os
import hashlib
from time import time
from tqdm import tqdm
from pkcs11 import ObjectClass, Mechanism, Attribute

lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')
pin = '1234'

with token.open(rw=True, user_pin=pin) as session:
    pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 2048, store=True)

    iterations = 1000  
    data_length = 5

    print(pub.__dict__)
    print(priv.__dict__)

    print("Testing Encryption")

    t0 = time()
    for i in tqdm(range(iterations)):
        data = os.urandom(data_length)
        cc = pub.encrypt(data)

    d = time()-t0

    print(f"Encrypt speed: {iterations/d}")

    print("Testing Decryption")
    cc = cc[:256]
    t0 = time()
    for i in tqdm(range(iterations)):
        # cc = priv.sign(data)
        pc = priv.decrypt(cc)

    d = time()-t0

    print(f"Decrypt speed: {iterations/d}")

    print("Testing Sign")

    t0 = time()
    for i in tqdm(range(iterations)):
        data = os.urandom(data_length)
        digest = hashlib.sha256(data).digest()
        cc = priv.sign(digest, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

    d = time()-t0

    print(f"Sign speed: {iterations/d}")

    print("Testing Verify")

    t0 = time()
    for i in tqdm(range(iterations)):
        verify = pub.verify(digest, cc, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

    d = time()-t0

    print(f"Verify speed: {iterations/d}")
