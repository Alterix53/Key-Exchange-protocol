# Needham-Schroeder Public Key Exchange (14.2.py)

## Muc tieu
File `14.2.py` mo phong giao thuc Needham-Schroeder khoa cong khai de:
- Xac thuc hai chieu giua Alice va Bob.
- Thiet lap session key bi mat `Ks`.

## Cac buoc giao thuc duoc mo phong
1. A -> B: `E(PUb, IDA || N1)`
2. B -> A: `E(PUa, N1 || N2)`
3. A -> B: `E(PUb, N2)`
4. A -> B: `E(PUb, Ks)` va `Sign(PRa, Ks)`
5. B giai ma `Ks` bang `PRb`, sau do verify chu ky bang `PUa`

## Cac ham trong file
- Quan ly khoa:
	- `generate_keypair`
	- `save_keypair_to_files`
	- `load_keypair_from_files`
	- `get_or_create_keypair`
- Toan tu RSA:
	- `rsa_encrypt` (OAEP + SHA-256)
	- `rsa_decrypt` (OAEP + SHA-256)
	- `rsa_sign` (PSS + SHA-256)
	- `rsa_verify` (PSS + SHA-256)
- Ho tro payload:
	- `new_nonce`
	- `pack`
	- `unpack`
- Chay mo phong:
	- `run_protocol`

## Du lieu sinh ra
- Khoa duoc luu tai:
	- `keys/alice/priv.pem`, `keys/alice/pub.pem`
	- `keys/bob/priv.pem`, `keys/bob/pub.pem`
- Lan dau chay se tao khoa moi, cac lan sau se load lai tu file.

## Cach chay
Tu thu muc `Full_Public_Key_Exchange`:

```bash
python 14.2.py
```

## Ket qua mong doi
- Bob verify chu ky cua Alice thanh cong.
- `Alice's Ks` va `Bob's Ks` giong nhau.
- Neu `N1` hoac `N2` khong khop, chuong trinh dung bang `assert` de bao dau hieu bat thuong.

## Gioi han cua ban mo phong
- Day la mo phong trong 1 process, khong phai giao tiep qua socket that.
- Chua gom timestamp/anti-replay nang cao, chu yeu minh hoa logic cot loi cua giao thuc.
