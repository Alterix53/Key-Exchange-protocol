import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# 1. Alice sinh khóa RSA
pr_a = rsa.generate_private_key(65537, 2048)
pu_a_pem = pr_a.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def start_alice():
    # Alice kết nối tới port 8000 (nơi Darth đang đứng)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 8000))
    
    # 2. Gửi ID và Public Key
    id_a = "Alice_01"
    payload = f"{id_a}|{pu_a_pem.decode()}"
    client.send(payload.encode())
    print("[Alice] Đã gửi Public Key và ID.")

    # 3. Nhận lại Session Key mã hóa
    encrypted_ks = client.recv(4096)
    
    # 4. Giải mã bằng Private Key của mình
    ks = pr_a.decrypt(
        encrypted_ks,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"[Alice] Đã giải mã thành công Session Key: {ks.decode()}")
    client.close()

if __name__ == "__main__":
    start_alice()