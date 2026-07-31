#!/usr/bin/env python3
"""
generate_challenge.py
----------------------
Builds a self-contained "Weak RSA" cryptography CTF challenge.

The vulnerability taught by this challenge:
    RSA is only secure if the modulus n = p * q uses two LARGE,
    well-separated primes. Here we deliberately choose small primes,
    so n can be factored in seconds with simple tools (Pollard's rho,
    or even sympy.factorint / online factordb). Once p and q are known,
    the private key can be rebuilt and the flag decrypted.

Run:
    python3 generate_challenge.py

Output (in ./output/):
    challenge.txt   -> hand this file to your opponent (public info only)
    README.md       -> the challenge prompt/instructions for your opponent
    solution.txt    -> KEEP THIS FOR YOURSELF (contains p, q, d, flag) - do not share!

Each run generates a NEW random flag and NEW primes, so the challenge
is different every time.
"""

import os
import random
import string
import secrets
from sympy import randprime, isprime

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def generate_flag(length=16):
    """Creates a random flag in the classic flag{...} CTF format."""
    charset = string.ascii_lowercase + string.digits
    body = ''.join(secrets.choice(charset) for _ in range(length))
    return f"flag{{{body}}}"


def generate_small_prime(bits):
    """Generate a random prime with roughly `bits` bits (deliberately small)."""
    low = 2 ** (bits - 1)
    high = 2 ** bits - 1
    return randprime(low, high)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x, y = egcd(b % a, a)
    return (g, y - (b // a) * x, x)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("modular inverse does not exist")
    return x % m


def build_rsa_challenge(flag: str, prime_bits: int = 20):
    """
    Builds weak RSA keys and encrypts the flag.

    Since we deliberately keep the primes SMALL (so the modulus n is easy
    to factor -- that's the whole point of the challenge), n is too small
    to hold the entire flag as one integer. So we block-encrypt: the flag
    is split into small byte-chunks, and each chunk is RSA-encrypted
    separately. This is a common real-world pattern too (RSA is normally
    only ever used to encrypt small values, like an AES key).

    prime_bits controls the difficulty:
        16-20 bits -> trivial, factors instantly
        24-28 bits -> still fast (<1s with Pollard's rho / sympy)
        32+ bits   -> more of a "real" challenge, still very solvable
    """
    p = generate_small_prime(prime_bits)
    q = generate_small_prime(prime_bits)
    while q == p:
        q = generate_small_prime(prime_bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if egcd(e, phi)[0] != 1:
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2

    d = modinv(e, phi)

    # Leave a safety margin below n's bit length so every chunk is < n.
    chunk_bytes = max(1, (n.bit_length() - 8) // 8)

    flag_bytes = flag.encode()
    chunks = [flag_bytes[i:i + chunk_bytes] for i in range(0, len(flag_bytes), chunk_bytes)]

    c_list = []
    m_list = []
    for chunk in chunks:
        m = int.from_bytes(chunk, "big")
        if m >= n:
            raise ValueError("chunking error: a chunk is not smaller than n")
        m_list.append(m)
        c_list.append(pow(m, e, n))

    return {
        "p": p, "q": q, "n": n, "phi": phi,
        "e": e, "d": d,
        "m_list": m_list, "c_list": c_list,
        "chunk_bytes": chunk_bytes,
    }


def write_outputs(data: dict, flag: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    c_list_str = ", ".join(str(c) for c in data["c_list"])

    # --- Files for the OPPONENT (public only) ---
    challenge_txt = f"""n = {data['n']}
e = {data['e']}
c_list = [{c_list_str}]
"""
    with open(os.path.join(OUTPUT_DIR, "challenge.txt"), "w") as f:
        f.write(challenge_txt)

    readme_md = f"""# Crypto Challenge: "Weak Keys"

You intercepted an RSA-encrypted message. Recover the plaintext flag.

## Files provided
- `challenge.txt` — contains the public modulus `n`, public exponent `e`,
  and a list of ciphertext blocks `c_list` (the flag was too long for a
  single RSA block, so it was split into chunks and each chunk encrypted
  separately, in order).

## Your task
1. Factor `n` into its two prime factors `p` and `q`.
   (Hint: this modulus was NOT generated safely — the primes are small
   enough to factor quickly. Try `sympy.factorint(n)`, Pollard's rho,
   or even an online factorization tool.)
2. Rebuild the private exponent `d`:
   - `phi = (p - 1) * (q - 1)`
   - `d = modular_inverse(e, phi)`
3. Decrypt each block: `m_i = pow(c_i, d, n)` for every `c_i` in `c_list`.
4. Convert each `m_i` back to bytes and concatenate them in order to
   reveal the flag.
   In Python: `m.to_bytes((m.bit_length() + 7) // 8, "big")`

## Flag format
`flag{{...}}`

Good luck!
"""
    with open(os.path.join(OUTPUT_DIR, "README.md"), "w") as f:
        f.write(readme_md)

    # --- File for YOU ONLY (do not hand this out) ---
    m_list_str = ", ".join(str(m) for m in data["m_list"])
    solution_txt = f"""SOLUTION - KEEP PRIVATE - DO NOT SHARE WITH OPPONENT

flag       = {flag}
p          = {data['p']}
q          = {data['q']}
n          = {data['n']}
phi        = {data['phi']}
e          = {data['e']}
d          = {data['d']}
chunk_bytes= {data['chunk_bytes']}
m_list     = [{m_list_str}]
c_list     = [{c_list_str}]
"""
    with open(os.path.join(OUTPUT_DIR, "solution.txt"), "w") as f:
        f.write(solution_txt)


def main():
    flag = generate_flag()
    data = build_rsa_challenge(flag, prime_bits=24)
    write_outputs(data, flag)
    print("Challenge generated successfully in ./output/")
    print(f"  - challenge.txt  (give to opponent)")
    print(f"  - README.md      (give to opponent)")
    print(f"  - solution.txt   (KEEP PRIVATE)")
    print()
    print(f"Flag for this run: {flag}")


if __name__ == "__main__":
    main()
