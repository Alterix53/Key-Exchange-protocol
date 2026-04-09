"""
Needham-Schroeder Public Key Protocol (NEED78)
================================================
Provides mutual authentication + confidential session key exchange.

Protocol Steps:
  1. A → B : E(PUb, IDA || N1)
  2. B → A : E(PUa, N1 || N2)
  3. A → B : E(PUb, N2)
  4. A → B : E(PUb, Ks)  ||  Sign(PRa, Ks)
             [textbook: E(PUb, E(PRa, Ks)) — "E with private key" = signing]
  5. B recovers Ks : D(PRb, cipher) then verifies Sign(PRa, Ks) with PUa
"""

import os, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ─── Helpers ──────────────────────────────────────────────────────────────────

def generate_keypair(name):
    pr = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                  backend=default_backend())
    print(f"[SETUP] Generated RSA-2048 key pair for {name}")
    return pr, pr.public_key()

def save_keypair_to_files(prv, pub, priv_path, pub_path):
    os.makedirs(os.path.dirname(priv_path), exist_ok=True)
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)

    with open(priv_path, "wb") as f:
        f.write(prv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_keypair_from_files(name, priv_path, pub_path):
    with open(priv_path, "rb") as f:
        prv = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())

    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(
            f.read(), backend=default_backend())

    print(f"[SETUP] Loaded RSA key pair for {name} from files")
    return prv, pub

def get_or_create_keypair(name, owner_dir):
    priv_path = os.path.join(owner_dir, "priv.pem")
    pub_path = os.path.join(owner_dir, "pub.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return load_keypair_from_files(name, priv_path, pub_path)

    prv, pub = generate_keypair(name)
    save_keypair_to_files(prv, pub, priv_path, pub_path)
    print(f"[SETUP] Saved keys for {name} to {owner_dir}")
    return prv, pub

def rsa_encrypt(pub, data):
    return pub.encrypt(data, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(prv, data):
    return prv.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_sign(prv, data):
    return prv.sign(data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def rsa_verify(pub, sig, data):
    pub.verify(sig, data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def new_nonce(label):
    n = os.urandom(16)
    print(f"  [NONCE] {label} = {n.hex()}")
    return n

def pack(*fields):
    return json.dumps([base64.b64encode(f).decode() for f in fields]).encode()

def unpack(data, count):
    parts = json.loads(data.decode())
    assert len(parts) == count
    return [base64.b64decode(p) for p in parts]

# ─── Protocol ─────────────────────────────────────────────────────────────────

def run_protocol():
    SEP = "─" * 62
    print("=" * 62)
    print("   Needham-Schroeder Public Key Protocol  (NEED78)")
    print("=" * 62)

    # Setup
    print("\n[SETUP] Load keys from PEM files (or generate once if missing) …")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    alice_dir = os.path.join(base_dir, "keys", "alice")
    bob_dir = os.path.join(base_dir, "keys", "bob")
    PRa, PUa = get_or_create_keypair("A (Alice)", alice_dir)
    PRb, PUb = get_or_create_keypair("B (Bob)", bob_dir)
    IDA = b"Alice"

    # ── Step 1: A → B : E(PUb, IDA ‖ N1) ─────────────────────────────────────
    print(f"\n{SEP}\nSTEP 1  A → B :  E(PUb, IDA ‖ N1)\n{SEP}")
    N1 = new_nonce("N1")
    msg1 = rsa_encrypt(PUb, pack(IDA, N1))
    print(f"  Alice sends ciphertext ({len(msg1)} B) to Bob")

    # ── Step 2: B → A : E(PUa, N1 ‖ N2) ─────────────────────────────────────
    print(f"\n{SEP}\nSTEP 2  B → A :  E(PUa, N1 ‖ N2)\n{SEP}")
    recv_IDA, recv_N1 = unpack(rsa_decrypt(PRb, msg1), 2)
    assert recv_IDA == IDA, "Bob: IDA mismatch!"
    print(f"  Bob decrypted  IDA = {recv_IDA.decode()!r}  ✓")
    print(f"  Bob sees       N1  = {recv_N1.hex()}")
    N2 = new_nonce("N2")
    msg2 = rsa_encrypt(PUa, pack(recv_N1, N2))
    print(f"  Bob sends ciphertext ({len(msg2)} B) to Alice")

    # ── Step 3: A → B : E(PUb, N2) ───────────────────────────────────────────
    print(f"\n{SEP}\nSTEP 3  A → B :  E(PUb, N2)   [Alice authenticates to Bob]\n{SEP}")
    echo_N1, recv_N2 = unpack(rsa_decrypt(PRa, msg2), 2)
    assert echo_N1 == N1, "Alice: N1 mismatch — possible MITM!"
    print(f"  Alice sees echoed N1 = {echo_N1.hex()}")
    print(f"  N1 matches ✓  →  correspondent is indeed Bob")
    print(f"  Alice sees N2        = {recv_N2.hex()}")
    msg3 = rsa_encrypt(PUb, pack(recv_N2))
    print(f"  Alice sends E(PUb, N2) ({len(msg3)} B) to Bob")

    # ── Step 4: A → B : E(PUb, Ks) ‖ Sign(PRa, Ks) ──────────────────────────
    print(f"\n{SEP}\nSTEP 4  A → B :  E(PUb, Ks)  ‖  Sign(PRa, Ks)")
    print(        f"        [textbook notation: E(PUb, E(PRa, Ks))]\n{SEP}")
    echo_N2, = unpack(rsa_decrypt(PRb, msg3), 1)
    assert echo_N2 == N2, "Bob: N2 mismatch — possible MITM!"
    print(f"  Bob sees echoed N2 = {echo_N2.hex()}")
    print(f"  N2 matches ✓  →  correspondent is indeed Alice")

    Ks = os.urandom(32)      # 256-bit AES session key
    print(f"\n  Alice generates 256-bit session key:")
    print(f"    Ks = {Ks.hex()}")

    sig_Ks      = rsa_sign(PRa, Ks)        # "E(PRa, Ks)" — prove origin
    enc_Ks      = rsa_encrypt(PUb, Ks)     # "E(PUb, …)"  — ensure confidentiality
    print(f"\n  Sign(PRa, Ks)   → {len(sig_Ks)}-byte signature  (proves Alice sent it)")
    print(f"  E(PUb, Ks)      → {len(enc_Ks)}-byte ciphertext (only Bob can read)")

    # ── Step 5: B recovers Ks ────────────────────────────────────────────────
    print(f"\n{SEP}\nSTEP 5  B :  D(PRb, cipher)  then  Verify(PUa, sig, Ks)\n{SEP}")
    recv_Ks = rsa_decrypt(PRb, enc_Ks)
    rsa_verify(PUa, sig_Ks, recv_Ks)       # raises cryptography.exceptions.InvalidSignature if forged
    print(f"  Bob decrypted  Ks = {recv_Ks.hex()}")
    print(f"  Alice's signature verified with PUa ✓")

    # ── Result ────────────────────────────────────────────────────────────────
    assert Ks == recv_Ks
    print(f"\n{'=' * 62}")
    print("RESULT")
    print(f"{'=' * 62}")
    print(f"  Alice's Ks : {Ks.hex()}")
    print(f"  Bob's   Ks : {recv_Ks.hex()}")


if __name__ == "__main__":
    run_protocol()