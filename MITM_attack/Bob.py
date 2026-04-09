import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# 1. Khởi tạo khóa của Bob
pr_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pu_b = pr_b.public_key()

def start_bob():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 9000)) # Bob lắng nghe tại port 9000
    server.listen(1)
    print("[Bob] Đang chờ kết nối...")
    
    conn, addr = server.accept()
    
    # 2. Nhận gói tin từ Alice (Thực tế là từ Darth)
    # Gói tin có dạng: "ID_A | PUBLIC_KEY_PEM"
    data = conn.recv(4096).decode().split('|')
    id_a = data[0]
    pu_a_pem = data[1].encode()
    
    # Load Public Key nhận được (Bob tưởng là của Alice)
    received_pu_a = serialization.load_pem_public_key(pu_a_pem)
    print(f"[Bob] Đã nhận Public Key từ {id_a}. Đang tạo Session Key...")

    # 3. Tạo Session Key (Khóa phiên)
    session_key = b"SESSION-KEY-ABC-123-XYZ"
    
    # 4. Mã hóa Session Key bằng Public Key đã nhận
    if isinstance(received_pu_a, rsa.RSAPublicKey):
        encrypted_ks = received_pu_a.encrypt(
            session_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    
    conn.send(encrypted_ks)
    print(f"[Bob] Đã gửi lại Session Key mã hóa.")
    conn.close()

if __name__ == "__main__":
    start_bob()