import pkcs11, os
from time import time
from tqdm import tqdm
import hashlib
print(pkcs11.__file__)
# Initialise our PKCS#11 library
lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')

data = b'INPUT DATA'

# Open a session on our token
with token.open(rw=True, user_pin='1234') as session:
    # Generate an EC keypair in this session from a named curve
    ecparams = session.create_domain_parameters(
        pkcs11.KeyType.EC, {
            pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp384r1'),
            # pkcs11.Attribute.EC_PARAMS: b'\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07'
        }, local=True)
    
    attributes = {
        pkcs11.Attribute.DECRYPT: True,
        pkcs11.Attribute.VERIFY: True,
        pkcs11.Attribute.SIGN: True,
        pkcs11.Attribute.ENCRYPT: True,
    }

    pub, priv = ecparams.generate_keypair(store=True, public_template=attributes, private_template=attributes)
    # Sign
    iterations = 1000   
    data_length = 100


    t0 = time()
    for i in tqdm(range(iterations)):
        data = os.urandom(data_length)
        digest = hashlib.sha256(data).digest()
        cc = priv.sign(digest, mechanism=pkcs11.Mechanism.ECDSA)

    d = time()-t0

    print(iterations/d)

    t0 = time()
    for i in tqdm(range(iterations)):
        verify = priv.verify(digest, cc, mechanism=pkcs11.Mechanism.ECDSA)

    d = time()-t0

    print(iterations/d)
