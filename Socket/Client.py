import socket
import base64
import os
import struct
from pathlib import Path
from typing import cast
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

PRIVATE_KEYS_DIR = Path(__file__).resolve().parent / "PrivateKeys"


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
    payload_len = struct.unpack("!I", header)[0]
    return recv_exact(sock, payload_len)

def get_current_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Không cần kết nối thật, chỉ để hệ điều hành chọn interface phù hợp
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

class CryptoClient:
    def __init__(self, user_id, create_if_missing=True):
        self.user_id = user_id
        self.server_addr = (get_current_ip(), 9999)
        self.private_key: RSAPrivateKey = self._load_or_create_private_key(create_if_missing=create_if_missing)
        self.public_key: RSAPublicKey = self.private_key.public_key()

    def _private_key_path(self):
        return PRIVATE_KEYS_DIR / f"{self.user_id}.pem"

    def _save_private_key(self):
        PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        pem_data = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._private_key_path().write_bytes(pem_data)

    def _load_or_create_private_key(self, create_if_missing=True) -> RSAPrivateKey:
        key_path = self._private_key_path()
        if key_path.exists():
            return cast(RSAPrivateKey, serialization.load_pem_private_key(key_path.read_bytes(), password=None))

        if not create_if_missing:
            raise FileNotFoundError(f"Khong tim thay khoa rieng cua {self.user_id}.")

        # Tạo cặp khóa RSA cho riêng mình
        private_key = rsa.generate_private_key(65537, 2048)
        PRIVATE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem_data)
        return cast(RSAPrivateKey, private_key)

    def get_pub_bytes(self):
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def register(self):
        #  Gửi khóa công khai lên Server Authority
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.server_addr)
        msg = f"REGISTER|{self.user_id}|{self.get_pub_bytes()}"
        send_frame(s, msg.encode())
        print(f"[{self.user_id}] {recv_frame(s).decode()}")
        self._save_private_key()
        s.close()

    def get_other_public_key(self, target_id):
        # [cite: 135] Truy vấn khóa của đối phương từ danh bạ
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.server_addr)
        send_frame(s, f"REQUEST|{target_id}".encode())
        key_data = recv_frame(s)
        s.close()
        
        if key_data == b"NOT_FOUND": return None
        return cast(RSAPublicKey, serialization.load_pem_public_key(key_data))

    def get_registered_ids(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.server_addr)
        send_frame(s, b"LIST")
        ids_data = recv_frame(s).decode()
        s.close()
        if not ids_data.strip():
            return []
        return [item for item in ids_data.split("|") if item]

    def send_session_key(self, receiver_id):
        receiver_public_key = self.get_other_public_key(receiver_id)
        if receiver_public_key is None:
            print(f"[!] Khong tim thay khoa cong khai cua {receiver_id}.")
            return
        if not isinstance(receiver_public_key, RSAPublicKey):
            print(f"[!] Khoa cua {receiver_id} khong phai RSA public key.")
            return

        session_key = os.urandom(32)
        encrypted_session_key = receiver_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_b64 = base64.b64encode(encrypted_session_key).decode()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.server_addr)
        send_frame(s, f"SEND_SESSION|{self.user_id}|{receiver_id}|{encrypted_b64}".encode())
        response = recv_frame(s).decode()
        s.close()

        if response == "SUCCESS":
            print(f"[+] Da gui session key den {receiver_id}.")
            print(f"    Session key (hex): {session_key.hex()}")
        elif response == "NOT_FOUND":
            print(f"[!] Khong tim thay nguoi nhan {receiver_id} tren server.")
        else:
            print(f"[!] Gui session key that bai: {response}")

    def receive_session_key(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.server_addr)
        send_frame(s, f"RECEIVE_SESSION|{self.user_id}".encode())
        response = recv_frame(s).decode()
        s.close()

        if response == "NOT_FOUND":
            print("[!] Khong co session key nao dang cho ban.")
            return

        sender_id, encrypted_b64 = response.split("|", 1)
        encrypted_session_key = base64.b64decode(encrypted_b64.encode())
        session_key = self.private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"[+] Da nhan session key tu {sender_id}.")
        print(f"    Session key (hex): {session_key.hex()}")


def show_authenticated_menu(client):
    while True:
        print(f"\nDang dang nhap voi user: {client.user_id}")
        print("1. Lay key")
        print("2. Gui session key")
        print("3. Nhan session key")
        print("4. Dang xuat")
        print("0. Thoat")
        choice = input("Nhap lua chon: ").strip()

        if choice == "1":
            ids = client.get_registered_ids()
            if not ids:
                print("[!] Chua co khoa cong khai nao tren server.")
                continue

            print("Danh sach khoa cong khai tren server:")
            for idx, name in enumerate(ids, start=1):
                print(f"{idx}. {name}")

            target_id = input("Nhap dung ten can lay key: ").strip()
            if not target_id:
                print("[!] Ten can lay key khong duoc rong.")
                continue

            public_key = client.get_other_public_key(target_id)
            if public_key is None:
                print("[!] Khong tim thay khoa voi ten da nhap.")
            else:
                print(f"[+] Da lay thanh cong khoa cong khai cua {target_id}.")

        elif choice == "2":
            receiver_id = input("Nhap ten nguoi nhan: ").strip()
            if not receiver_id:
                print("[!] Ten nguoi nhan khong duoc rong.")
                continue
            client.send_session_key(receiver_id)

        elif choice == "3":
            client.receive_session_key()

        elif choice == "4":
            print(f"[+] Da dang xuat khoi {client.user_id}.")
            break

        elif choice == "0":
            print("[+] Ket thuc chuong trinh.")
            raise SystemExit

        else:
            print("[!] Lua chon khong hop le. Vui long chon 0, 1, 2, 3 hoac 4.")


def check_server_connection(server_addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(server_addr)
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_menu():
    server_addr = (get_current_ip(), 9999)
    if not check_server_connection(server_addr):
        print("[!] Khong ket noi duoc Server. Hay mo Server truoc.")
        return

    print("[+] Da ket noi Server Authority.")
    while True:
        print("\nChon thao tac:")
        print("1. Dang ky")
        print("2. Dang nhap")
        print("0. Thoat")
        choice = input("Nhap lua chon: ").strip()

        if choice == "1":
            user_id = input("Nhap ten dang ky: ").strip()
            if not user_id:
                print("[!] Ten dang ky khong duoc rong.")
                continue
            client = CryptoClient(user_id)
            client.register()
            show_authenticated_menu(client)

        elif choice == "2":
            user_id = input("Nhap ten dang nhap: ").strip()
            if not user_id:
                print("[!] Ten dang nhap khong duoc rong.")
                continue

            try:
                client = CryptoClient(user_id, create_if_missing=False)
            except FileNotFoundError:
                print(f"[!] Khong tim thay khoa rieng local cua {user_id}. Hay dang ky truoc.")
                continue

            if user_id not in client.get_registered_ids():
                print(f"[!] {user_id} chua co tren server. Hay dang ky truoc.")
                continue

            print(f"[+] Dang nhap thanh cong voi {user_id}.")
            show_authenticated_menu(client)

        elif choice == "0":
            print("[+] Ket thuc chuong trinh.")
            break

        else:
            print("[!] Lua chon khong hop le. Vui long chon 0, 1 hoac 2.")

if __name__ == "__main__":
    run_menu()