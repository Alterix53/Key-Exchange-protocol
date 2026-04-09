import socket
import threading
import struct
from pathlib import Path

# Lưu trữ dưới dạng { "ID": b"PublicKeyBytes" }
public_key_directory = {}
pending_session_keys = {}
directory_lock = threading.Lock()
KEYS_DIR = Path(__file__).resolve().parent / "Keys"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Client dong ket noi trong luc gui du lieu")
        data += chunk
    return data


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    payload_len = struct.unpack("!I", header)[0]
    return recv_exact(sock, payload_len)


def save_public_key_to_file(user_id, pub_key):
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_path = KEYS_DIR / f"{user_id}.pem"
    key_path.write_text(pub_key, encoding="utf-8")
    return key_path


def load_public_keys_from_files():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    for pem_file in KEYS_DIR.glob("*.pem"):
        user_id = pem_file.stem
        public_key_directory[user_id] = pem_file.read_text(encoding="utf-8")


def list_registered_ids():
    # Trả về danh sách tên đã có trên server (đã đăng ký hoặc đã lưu file)
    with directory_lock:
        memory_ids = set(public_key_directory.keys())
        file_ids = {pem_file.stem for pem_file in KEYS_DIR.glob("*.pem")}
        return sorted(memory_ids | file_ids)


def store_session_key(sender_id, receiver_id, encrypted_session_key):
    with directory_lock:
        pending_session_keys.setdefault(receiver_id, []).append((sender_id, encrypted_session_key))


def pop_session_key(receiver_id):
    with directory_lock:
        queue = pending_session_keys.get(receiver_id)
        if not queue:
            return None
        sender_id, encrypted_session_key = queue.pop(0)
        if not queue:
            pending_session_keys.pop(receiver_id, None)
        return sender_id, encrypted_session_key


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

def handle_client(client_socket):
    try:
        message = recv_frame(client_socket).decode()
        command = message.split("|", 1)[0]

        if command == "REGISTER":
            #  Người dùng đăng ký khóa công khai
            _, user_id, pub_key = message.split("|", 2)
            with directory_lock:
                public_key_directory[user_id] = pub_key
            saved_path = save_public_key_to_file(user_id, pub_key)
            print(f"[*] Đã đăng ký khóa cho: {user_id}")
            print(f"[*] Đã lưu khóa công khai tại: {saved_path}")
            send_frame(client_socket, b"SUCCESS")

        elif command == "REQUEST":
            # [cite: 135] Người dùng yêu cầu khóa của người khác
            _, target_id = message.split("|", 1)
            if target_id in public_key_directory:
                send_frame(client_socket, public_key_directory[target_id].encode())
            else:
                key_path = KEYS_DIR / f"{target_id}.pem"
                if key_path.exists():
                    key_data = key_path.read_text(encoding="utf-8")
                    public_key_directory[target_id] = key_data
                    send_frame(client_socket, key_data.encode())
                else:
                    send_frame(client_socket, b"NOT_FOUND")

        elif command == "LIST":
            send_frame(client_socket, "|".join(list_registered_ids()).encode())

        elif command == "SEND_SESSION":
            _, sender_id, receiver_id, encrypted_session_key = message.split("|", 3)
            if receiver_id not in list_registered_ids():
                send_frame(client_socket, b"NOT_FOUND")
            else:
                store_session_key(sender_id, receiver_id, encrypted_session_key)
                print(f"[*] Session key da duoc gui tu {sender_id} den {receiver_id}")
                send_frame(client_socket, b"SUCCESS")

        elif command == "RECEIVE_SESSION":
            _, receiver_id = message.split("|", 1)
            session_item = pop_session_key(receiver_id)
            if session_item is None:
                send_frame(client_socket, b"NOT_FOUND")
            else:
                sender_id, encrypted_session_key = session_item
                send_frame(client_socket, f"{sender_id}|{encrypted_session_key}".encode())
    except (ValueError, ConnectionError) as exc:
        print(f"[!] Loi xu ly client: {exc}")
    finally:
        client_socket.close()

def start_server():
    load_public_keys_from_files()
    ip = get_current_ip()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, 9999))
    server.listen(5)
    print(f"[+] Server Authority đang chạy tại {ip}:9999...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == "__main__":
    start_server()