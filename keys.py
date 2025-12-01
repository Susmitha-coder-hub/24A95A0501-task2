from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair

    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Convert private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Convert public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


# Generate keys
private_pem, public_pem = generate_rsa_keypair()

# Save to required filenames
with open("student_private.pem", "wb") as f:
    f.write(private_pem)

with open("student_public.pem", "wb") as f:
    f.write(public_pem)

print("Keys generated successfully!")
