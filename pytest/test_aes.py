import pkcs11, os
print(pkcs11.__file__)
# Initialise our PKCS#11 library
lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')

data = b'INPUT DATA'

# Open a session on our token
with token.open(rw=True, user_pin='1234') as session:
    key = session.generate_key(pkcs11.KeyType.AES, 256, store=True)

    # Get an initialisation vector
    iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
    # Encrypt our data
    crypttext = key.encrypt(data, mechanism_param=iv)
