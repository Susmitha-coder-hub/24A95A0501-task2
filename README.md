
# 24A95A0501-task2
 f7a26bb5d36d62a8cfcc10e5814a7d299ee98a28
24A95A0501
Nandhigramam Lakshmi Susmitha
CSE 3rd year

This repository is used for implementing a micro-service that works with the instructor API.
The service must:

Run a REST API on port 8080.

Implement endpoints for:

/decrypt-seed – decrypt instructor data using the student private RSA key (4096-bit, OAEP SHA-256).

/generate-2fa – generate a TOTP (SHA-1, 6 digits, 30-second interval).

/verify-2fa – verify the TOTP with ±1 time-step tolerance.

Store the decrypted seed in /data/seed.txt (must persist between restarts).

Run a cron job every minute that generates a TOTP and logs it to /cron/last_code.txt in UTC.

Be packaged in a Docker multi-stage build, set to UTC timezone, and expose port 8080.

 HEAD
Clone this GitHub repository using the exact URL provided.

Clone this GitHub repository using the exact URL provided.

