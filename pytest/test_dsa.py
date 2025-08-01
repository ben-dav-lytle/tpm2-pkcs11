import pkcs11, os
print(pkcs11.__file__)
# Initialise our PKCS#11 library
lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')

data = b'INPUT DATA'

# Open a session on our token
with token.open(rw=True, user_pin='1234') as session:
    # Generate a DES key in this session
    pub, priv = session.generate_keypair(pkcs11.KeyType.DSA, 1024, store=True)

    # Sign
    signature = priv.sign(data)