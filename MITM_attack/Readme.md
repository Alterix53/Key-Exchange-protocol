## Mô phỏng Tấn công Man-in-the-Middle (MITM) trên RSA (giao thức thứ 2 trong 14.2)
Dự án này minh họa cách một kẻ tấn công (Darth) có thể can thiệp vào quá trình trao đổi khóa công khai giữa Alice và Bob để đánh cắp Session Key (Khóa phiên).

### Kịch bản hệ thống
- Alice: Client muốn thiết lập kết nối an toàn với Bob.
- Bob: Server cung cấp Session Key được mã hóa bằng Public Key của Alice.
- Darth: Kẻ đứng giữa, thực hiện đánh tráo Public Key và giải mã thông tin nhạy cảm.

### Quy trình tấn công (Sơ đồ)
- Alice gửi {PUa, IDa} hướng tới Bob nhưng bị Darth chặn lại.
- Darth lưu trữ PUa thật, sau đó gửi {PUd, IDa} cho Bob.
- Bob tin rằng PUd là của Alice, dùng nó để mã hóa Ks (Session Key) thành E(PUd, Ks).
- Darth chặn gói tin từ Bob, dùng PRd của mình để giải mã lấy Ks.
- Darth mã hóa lại Ks bằng PUa thật và gửi cho Alice để duy trì sự tin tưởng.

### Cách chạy:
- Mở 3 terminal riêng biệt.
- Chạy file Proxy_Drath.py trước (đóng vai người nằm giữa nghe lén).
- Chạy File Bob.py 
- Chạy File Alice.py
Sau khi file Alice.py chạy, toàn bộ Alice, Bob và Drath đều có được session key (in ra màn hình terminal).