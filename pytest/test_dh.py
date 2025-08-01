import pkcs11, os
print(pkcs11.__file__)
# Initialise our PKCS#11 library
lib = pkcs11.lib("/home/bowen/tpm2-pkcs11/src/.libs/libtpm2_pkcs11.so.0.0.0")
token = lib.get_token(token_label='test')

data = b'INPUT DATA'

# Open a session on our token
with token.open(rw=True, user_pin='1234') as session:
    parameters = session.create_domain_parameters(pkcs11.KeyType.DH, {
        pkcs11.Attribute.PRIME: 1,  # Diffie-Hellman parameters
        pkcs11.Attribute.BASE: 2,
    })

    # Generate a DH key pair from the public parameters
    public, private = parameters.generate_keypair(store=True)

    # Share the public half of it with our other party.
    _network_.write(public[Attribute.VALUE])
    # And get their shared value
    other_value = _network_.read()

    # Derive a shared session key with perfect forward secrecy
    session_key = private.derive_key(
        pkcs11.KeyType.AES, 128,
        mechanism_param=other_value)