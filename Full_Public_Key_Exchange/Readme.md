# Needham-Schroeder Public Key Exchange (14.2.py)

## Mục tiêu
File `14.2.py` mô phỏng giao thức Needham-Schroeder khóa công khai để:
- Xác thực hai chiều giữa Alice và Bob.
- Thiết lập session key bí mật `Ks`.

## Các bước giao thức được mô phỏng
1. A -> B: `E(PUb, IDA || N1)`
2. B -> A: `E(PUa, N1 || N2)`
3. A -> B: `E(PUb, N2)`
4. A -> B: `E(PUb, Ks)` và `Sign(PRa, Ks)`
5. B giải mã `Ks` bằng `PRb`, sau đó verify chữ ký bằng `PUa`

## Các hàm trong file
- Quản lý khóa:
	- `generate_keypair`
	- `save_keypair_to_files`
	- `load_keypair_from_files`
	- `get_or_create_keypair`
- Toán tử RSA:
	- `rsa_encrypt` (OAEP + SHA-256)
	- `rsa_decrypt` (OAEP + SHA-256)
	- `rsa_sign` (PSS + SHA-256)
	- `rsa_verify` (PSS + SHA-256)
- Hỗ trợ payload:
	- `new_nonce`
	- `pack`
	- `unpack`
- Chạy mô phỏng:
	- `run_protocol`

## Dữ liệu sinh ra
- Khóa được lưu tại:
	- `keys/alice/priv.pem`, `keys/alice/pub.pem`
	- `keys/bob/priv.pem`, `keys/bob/pub.pem`
- Lần đầu chạy sẽ tạo khóa mới, các lần sau sẽ load lại từ file.

## Cách chạy
Từ thư mục `Full_Public_Key_Exchange`:

```bash
python 14.2.py
```

## Kết quả mong đợi
- Bob verify chữ ký của Alice thành công.
- Alice's Ks và Bob's Ks giống nhau.
- Nếu N1 hoặc N2 không khớp, chương trình dừng bằng assert để - báo dấu hiệu bất thường.
## Giới hạn của bản mô phỏng
- Đây là mô phỏng trong 1 process, không phải giao tiếp qua socket thật.
- Chưa gồm timestamp/anti-replay nâng cao, chủ yếu minh họa logic cốt lõi của giao thức.
