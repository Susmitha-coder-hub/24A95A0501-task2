#!/usr/bin/env python3
import requests
import datetime

try:
    # Call your generate-2fa endpoint
    response = requests.get("http://localhost:8080/generate-2fa")
    data = response.json()

    # Extract TOTP
    code = data.get("code", "ERROR")

    # Append timestamp + code to log file
    with open("/cron/last_code.txt", "a") as f:
        f.write(f"{datetime.datetime.utcnow()} - {code}\n")

except Exception as e:
    with open("/cron/last_code.txt", "a") as f:
        f.write(f"ERROR: {str(e)}\n")
