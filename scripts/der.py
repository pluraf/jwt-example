from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Load the public key
with open("public_key.der", "rb") as f:
    der_data = f.read()

public_key = serialization.load_der_public_key(der_data)
public_numbers = public_key.public_numbers()

x = public_numbers.x.to_bytes(32, byteorder='big')
y = public_numbers.y.to_bytes(32, byteorder='big')




print("X coordinate:", ", ".join(['0x' + x[i:i+4].hex() for i in range(0, len(x), 4)]))
print("Y coordinate:", ", ".join(['0x' + y[i:i+4].hex() for i in range(0, len(y), 4)]))
