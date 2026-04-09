import socket
import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def get_keys():
    priv = rsa.generate_private_key(65537, 2048)
    return priv, priv.public_key()

pr_a, pu_a = get_keys()
pu_a_pem = pu_a.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Ket noi bi dong trong luc nhan du lieu")
        data += chunk
    return data


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    return recv_exact(sock, length)

def start_alice():
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect(('127.0.0.1', 9000))
    print("[ALICE] Đã kết nối tới Bob.")

    # --- BƯỚC TIỀN GIAO THỨC: Nhận Pub_B từ Bob ---
    pu_b_pem = recv_frame(alice)
    pu_b = serialization.load_pem_public_key(pu_b_pem)
    print("[ALICE] Đã nhận Public Key của Bob.")

    # --- BƯỚC 1: Gửi N1, IDA ---
    input("\n[BƯỚC 1] Nhấn Enter để gửi (N1 || ID_A)...")
    n1 = os.urandom(16)
    id_a = b"Alice_ID"
    encrypted1 = b""
    if isinstance(pu_b, rsa.RSAPublicKey):

        encrypted1 = pu_b.encrypt(
            n1 + id_a, 
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    send_frame(alice, encrypted1)
    send_frame(alice, pu_a_pem)

    # --- BƯỚC 2: Nhận N1, N2 ---
    print("\n[BƯỚC 2] Đang chờ Bob phản hồi...")
    data2 = recv_frame(alice)
    decrypted2 = pr_a.decrypt(
        data2, 
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    rec_n1 = decrypted2[:16]
    n2 = decrypted2[16:]
    if rec_n1 == n1:
        print(f" -> N1 khớp! Nhận được N2: {n2.hex()}")

    # --- BƯỚC 3: Gửi lại N2 ---
    input("\n[BƯỚC 3] Nhấn Enter để gửi lại N2 xác nhận...")
    if isinstance(pu_b, rsa.RSAPublicKey):
        packet3 = pu_b.encrypt(
            n2, 
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    send_frame(alice, packet3)

    # --- BƯỚC 4: Gửi Session Key ---
    input("\n[BƯỚC 4] Nhấn Enter để gửi Session Key (đã ký)...")
    ks = b"SECRET-KEY-2026"
    sig = pr_a.sign(ks, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(pu_b, rsa.RSAPublicKey):
        encrypted_ks = pu_b.encrypt(
            ks,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    send_frame(alice, encrypted_ks)
    send_frame(alice, sig)
    print(" -> Đã gửi Ks.")

    alice.close()

if __name__ == "__main__":
    start_alice()