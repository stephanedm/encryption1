#!/usr/bin/env python3
# dh_mitm_demo.py
# Educational demo: Diffie-Hellman + active MitM (Eve)
# Uses small numbers for clarity; DO NOT use these parameters in real crypto.

import hashlib

# Simple XOR stream cipher for demo (NOT secure in practice; used for demonstration)
def xor_bytes(key: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)

def derive_key_from_shared(shared_int: int) -> bytes:
    # deterministically derive a key (32 bytes) from the shared integer using SHA-256
    return hashlib.sha256(str(shared_int).encode()).digest()

def show(label, value):
    print(f"{label}: {value}")

def main():
    # Public DH parameters (small, for demo only)
    p = 23
    g = 5

    # Private secrets (in real life these are large and random)
    alice_priv = 6
    bob_priv   = 15

    # Eve's two secrets (one for the Alice<->Eve leg, one for the Eve<->Bob leg)
    eve_priv_to_bob   = 9   # e1
    eve_priv_to_alice = 13  # e2

    # Alice computes her public value A = g^a mod p
    A = pow(g, alice_priv, p)

    # Eve intercepts A and sends E1 = g^e1 to Bob (pretending to be Alice)
    E1 = pow(g, eve_priv_to_bob, p)

    # Bob computes his public B and sends it (intercepted by Eve)
    B = pow(g, bob_priv, p)

    # Eve intercepts B and sends E2 = g^e2 to Alice (pretending to be Bob)
    E2 = pow(g, eve_priv_to_alice, p)

    # Now compute the shared secrets each thinks they have
    shared_alice = pow(E2, alice_priv, p)         # Alice's view: (g^e2)^a = g^(a*e2)
    shared_bob   = pow(E1, bob_priv, p)           # Bob's view:   (g^e1)^b = g^(b*e1)

    # Eve can compute both secrets
    shared_eve_with_bob   = pow(B, eve_priv_to_bob, p)   # B^e1 = g^(b*e1)
    shared_eve_with_alice = pow(A, eve_priv_to_alice, p) # A^e2 = g^(a*e2)

    show("Public params p,g", f"{p}, {g}")
    show("Alice private a", alice_priv)
    show("Bob private b", bob_priv)
    show("Eve priv e1 (to Bob)", eve_priv_to_bob)
    show("Eve priv e2 (to Alice)", eve_priv_to_alice)
    print("---")
    show("Alice public A", A)
    show("Eve -> Bob (E1 sent)", E1)
    show("Bob public B", B)
    show("Eve -> Alice (E2 sent)", E2)
    print("---")
    show("Alice's computed shared secret", shared_alice)
    show("Bob's computed shared secret", shared_bob)
    show("Eve's shared secret with Bob", shared_eve_with_bob)
    show("Eve's shared secret with Alice", shared_eve_with_alice)
    print("---")

    # Derive symmetric keys (SHA-256 of the shared secret integer)
    key_alice = derive_key_from_shared(shared_alice)
    key_bob   = derive_key_from_shared(shared_bob)
    key_eve_ab = derive_key_from_shared(shared_eve_with_alice)  # Eve <-> Alice
    key_eve_bb = derive_key_from_shared(shared_eve_with_bob)    # Eve <-> Bob

    # Alice sends a message to Bob (but it goes through Eve)
    plaintext = b"Hello Bob, this is Alice. Secret: 42"
    show("Alice plaintext", plaintext.decode())

    # Alice encrypts under her shared key (with Eve posing as Bob she uses shared_alice)
    ct_from_alice = xor_bytes(key_alice, plaintext)
    show("Ciphertext on the wire (Alice->Eve)", ct_from_alice.hex())

    # Eve intercepts and decrypts using her key with Alice
    eve_reads = xor_bytes(key_eve_ab, ct_from_alice)
    show("Eve intercepts & decrypts (reads)", eve_reads.decode())

    # Eve may modify message (optional). Here she forwards the same plaintext.
    modified_for_bob = eve_reads  # no modification in this demo

    # Eve re-encrypts with key she shares with Bob and forwards to Bob
    ct_to_bob = xor_bytes(key_eve_bb, modified_for_bob)
    show("Ciphertext forwarded to Bob (Eve->Bob)", ct_to_bob.hex())

    # Bob decrypts using his shared key
    bob_receives = xor_bytes(key_bob, ct_to_bob)
    show("Bob decrypts and gets", bob_receives.decode())

    print("\nConclusion: Alice and Bob think they have a secure session with each other but Eve read the message.")

if __name__ == "__main__":
    main()
