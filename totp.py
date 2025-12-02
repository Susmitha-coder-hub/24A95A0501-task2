import base64
import pyotp


def hex_to_base32(hex_seed: str) -> str:
    """Convert 64-char hex seed → Base32 string."""
    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate a 6-digit TOTP code from 64-char hex seed.
    """
    base32_seed = hex_to_base32(hex_seed)

    totp = pyotp.TOTP(
        base32_seed,
        interval=30,      # 30-second period
        digits=6,         # 6-digit OTP
        digest="sha1"     # TOTP standard uses SHA-1
    )

    return totp.now()    # returns string like "123456"


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ±valid_window time periods.
    """
    base32_seed = hex_to_base32(hex_seed)

    totp = pyotp.TOTP(
        base32_seed,
        interval=30,
        digits=6,
        digest="sha1"
    )

    return totp.verify(code, valid_window=valid_window)


# Example usage
if __name__ == "__main__":
    hex_seed = "b4f8be0daa8379d3808b1ea2e34b3ebe439e5599eb961d6ebc53043a9b5909ef"  # YOUR decrypted seed

    code = generate_totp_code(hex_seed)
    print("Generated TOTP:", code)

    print("Verify:", verify_totp_code(hex_seed, code))
