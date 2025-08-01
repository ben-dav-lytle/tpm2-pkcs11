import pkcs11
import os
import hashlib
from time import time
from tqdm import tqdm
from pkcs11 import ObjectClass, Mechanism, Attribute

lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')
pin = '1234'


iterations = 100
print("Testing KeyGen")
tot = 0
    
for i in tqdm(range(iterations)):
    session = token.open(rw=True, user_pin=pin)

    t = time()

    ecparams = session.create_domain_parameters(
    pkcs11.KeyType.EC, {
        pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp384r1'),
    }, local=True)

    attributes = {
        pkcs11.Attribute.DECRYPT: True,
        pkcs11.Attribute.VERIFY: True,
        pkcs11.Attribute.SIGN: True,
        pkcs11.Attribute.ENCRYPT: True,
    }

    pub, priv = ecparams.generate_keypair(store=True, public_template=attributes, private_template=attributes)

    tot += time() - t

    session.close()

print(f"keyGen speed: {iterations/tot}")


