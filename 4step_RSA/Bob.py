import socket
import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def get_keys():
    priv = rsa.generate_private_key(65537, 2048)
    return priv, priv.public_key()

pr_b, pu_b = get_keys()
# Xuất khóa công khai của Bob ra định dạng PEM để gửi cho Alice
pu_b_pem = pu_b.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


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

def start_bob():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 9000))
    server.listen(1)
    print("[BOB] Đang đợi Alice kết nối...")
    conn, addr = server.accept()

    # --- BƯỚC TIỀN GIAO THỨC: Gửi Pub_B cho Alice ---
    send_frame(conn, pu_b_pem)
    print("[BOB] Đã gửi Public Key của Bob cho Alice.")

    # --- BƯỚC 1: Nhận N1, IDA ---
    print("\n[BƯỚC 1] Chờ Alice gửi gói tin...")
    encrypted_part = recv_frame(conn)
    pu_a_pem = recv_frame(conn)
    
    # Giải mã bằng Private Key của Bob
    decrypted1 = pr_b.decrypt(
        encrypted_part,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    pu_a = serialization.load_pem_public_key(pu_a_pem)
    n1 = decrypted1[:16]
    id_a = decrypted1[16:]
    print(f" -> Nhận thành công ID: {id_a.decode()}, N1: {n1.hex()}")

    # --- BƯỚC 2: Gửi N1, N2 ---
    input("\n[BƯỚC 2] Nhấn Enter để gửi phản hồi (N1 || N2)...")
    n2 = os.urandom(16)
    if isinstance(pu_a, rsa.RSAPublicKey):
        packet2 = pu_a.encrypt(
            n1 + n2, 
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    send_frame(conn, packet2)
    print(f" -> Đã gửi N1 và N2")

    # --- BƯỚC 3: Nhận xác nhận N2 ---
    print("\n[BƯỚC 3] Chờ Alice xác nhận N2...")
    data3 = recv_frame(conn)
    rec_n2 = pr_b.decrypt(
        data3, 
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    if rec_n2 == n2:
        print(" -> XÁC NHẬN: N2 khớp!")

    # --- BƯỚC 4: Nhận Session Key ---
    print("\n[BƯỚC 4] Chờ Alice gửi Session Key (Ks)...")
    encrypted_ks = recv_frame(conn)
    sig = recv_frame(conn)
    ks = pr_b.decrypt(
        encrypted_ks,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    try:
        if isinstance(pu_a, rsa.RSAPublicKey):
            pu_a.verify(sig, ks, padding.PKCS1v15(), hashes.SHA256())
        print(f" -> CHỮ KÝ HỢP LỆ! Session Key: {ks.decode()}")
    except:
        print(" -> LỖI: Chữ ký sai!")

    conn.close()

if __name__ == "__main__":
    start_bob()