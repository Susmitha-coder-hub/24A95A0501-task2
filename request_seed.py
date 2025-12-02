import json
import requests
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def request_seed(student_id, github_repo_url, api_url, public_key_path):
    # Read public key from file
    with open(public_key_path, "r") as f:
        public_key = f.read().strip()
        public_key = "\n".join(public_key.splitlines())  # normalize line endings

    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key
    }

    # Send request to API
    response = requests.post(api_url, json=payload, timeout=10)
    data = response.json()

    if data.get("status") != "success":
        raise Exception("API Error: " + json.dumps(data))

    encrypted_seed = data["encrypted_seed"]

    # Save encrypted seed to file
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)

    print(json.dumps(data, indent=2))  # Print API response

    return encrypted_seed

def decrypt_seed(encrypted_seed_b64, private_key_path):
    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Decode and decrypt
    encrypted_seed = base64.b64decode(encrypted_seed_b64)
    decrypted_seed = private_key.decrypt(
        encrypted_seed,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_seed.decode()

if __name__ == "__main__":
    student_id = "24A95A0501"
    github_repo_url = "https://github.com/Susmitha-coder-hub/24A95A0501-task3"
    api_url = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/"
    public_key_path = "student_public.pem"
    private_key_path = "student_private.pem"

    encrypted_seed = request_seed(student_id, github_repo_url, api_url, public_key_path)
    decrypted_seed = decrypt_seed(encrypted_seed, private_key_path)

    print("\nDecrypted Seed:\n", decrypted_seed)
