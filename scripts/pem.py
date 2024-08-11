from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load the public key from a PEM file
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Check if the key is EC and extract the numbers
if isinstance(public_key, ec.EllipticCurvePublicKey):
    numbers = public_key.public_numbers()
    x = numbers.x.to_bytes(32, byteorder='big')
    y = numbers.y.to_bytes(32, byteorder='big')

    print(", ".join([hex(i) for i in x]))
    print(", ".join([hex(i) for i in y]))

else:
    print("The key is not an EC public key.")