import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path="student_private.pem"):
    """Load RSA private key from PEM file."""
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt a Base64-encoded encrypted seed using RSA/OAEP with SHA-256.
    Returns a 64-character hexadecimal string.
    """
    ciphertext = base64.b64decode(encrypted_seed_b64)

    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    seed_hex = plaintext_bytes.decode("utf-8")

    if len(seed_hex) != 64:
        raise ValueError("Decrypted seed must be exactly 64 characters long.")

    valid_hex = "0123456789abcdef"
    if not all(c in valid_hex for c in seed_hex):
        raise ValueError("Seed contains invalid characters (must be hex).")

    return seed_hex


if __name__ == "__main__":
    try:
        private_key = load_private_key()

        # 👉 Paste your encrypted seed here
        encrypted_seed_example = "mpbJHbxVopTHHNIikFlOnzjwRtZnju1k19rIV1l5/Y/qKHQtr2FVBRSov2FN76fybhyGcOEkUcoo6fRKPYLKF8TN+rY5JMkoAXp8DGY729AzAEr9uJ+gDOKBOxDvU0iscbAfEzNGTyGjzhRCEuVJfTEn+YKo3b4jeo4zKLbVjnx/P/VGplWN+GaUHnwvFS80s1wIiQcUGM+lrEH/pueJbsW6s/0Nip/YHYwNRlA2bo5Z8j9wEpRRRJW7rtzuuF6MtAgTrHtPj6Vk1a2fM25BwgQxhZohBBnxDG6T53ckfLex2LTAyTAVlPeVjuv0ouTTNFOp5bHDNy4/MBZeoNGHt/bKgNTLKq4qVptZnsl3/JLxXVBwdsntHAWLt68rWYxGN7L2Ba3EFZrW1C0Y8kJlLIoR6YyjJuEa5pQDXQ1nSNl2R0mNuAU0IK9EcGNAv01VvXcY2uRffmVacIf/ycfHUvkRQsUtZxuNkFuM6xV2hvZj9prQ7QxFk3E5ZofJ8a0Z2pC5ksUAhfBwGurDdImt6J0tf5cWMR8CcqHxcYK1sQNy5E+phyfWI9NqTX8+SgIGvONHNdZF0viVkJ8+FVyw/wpiqxqLLElt5Vv02cGzvaF5wQFRNt63ip0DbvDAVJ3bcTiyYFHo+V7rAa6yYV7FOrf27cOFG13cvwvrc/GTsPY="

        seed = decrypt_seed(encrypted_seed_example, private_key)
        print("\nDecrypted Seed:", seed, "\n")

    except Exception as e:
        print("\nError:", e, "\n")
