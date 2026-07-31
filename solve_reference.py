#!/usr/bin/env python3
"""
solve_reference.py
-------------------
Reference solution for the "Weak Keys" RSA challenge.
Use this yourself to verify the generated challenge is solvable,
or to grade an opponent's/student's own solve script.

Usage:
    python3 solve_reference.py output/challenge.txt
"""

import sys
from sympy import factorint


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


def parse_challenge(path):
    values = {}
    with open(path) as f:
        content = f.read()

    for line in content.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if key == "c_list":
            values[key] = eval(val, {"__builtins__": {}})  # safe: only a literal list of ints
        else:
            values[key] = int(val)

    return values["n"], values["e"], values["c_list"]


def solve(n, e, c_list):
    # Step 1: factor n -> p, q (this is the "weak" step an attacker exploits)
    factors = factorint(n)
    primes = list(factors.keys())
    if len(primes) != 2:
        raise ValueError(f"Expected 2 prime factors, got: {factors}")
    p, q = primes

    # Step 2: rebuild private key
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)

    # Step 3: decrypt every block and reassemble
    flag_bytes = b""
    for c in c_list:
        m = pow(c, d, n)
        block = m.to_bytes((m.bit_length() + 7) // 8, "big")
        flag_bytes += block

    return p, q, d, flag_bytes.decode(errors="replace")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 solve_reference.py path/to/challenge.txt")
        sys.exit(1)

    n, e, c_list = parse_challenge(sys.argv[1])
    p, q, d, flag = solve(n, e, c_list)

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"d = {d}")
    print(f"Recovered flag: {flag}")


if __name__ == "__main__":
    main()
