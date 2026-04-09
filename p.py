from pypdf import PdfReader, PdfWriter

def cut_pdf(input_file, output_file, start_page, end_page):
    """
    Cắt nội dung PDF từ trang start_page đến end_page.
    Lưu ý: Trang bắt đầu tính từ 1.
    """
    try:
        # Đọc file PDF gốc
        reader = PdfReader(input_file)
        writer = PdfWriter()

        # Số trang thực tế trong Python bắt đầu từ 0
        # Nên ta cần trừ đi 1 cho start_page
        for page_num in range(start_page - 1, end_page):
            # Kiểm tra xem trang có tồn tại trong file không
            if page_num < len(reader.pages):
                writer.add_page(reader.pages[page_num])
            else:
                print(f"Cảnh báo: Trang {page_num + 1} vượt quá tổng số trang.")
                break

        # Lưu file mới
        with open(output_file, "wb") as output_stream:
            writer.write(output_stream)
        
        print(f"Thành công! Đã lưu các trang từ {start_page} đến {end_page} vào: {output_file}")

    except Exception as e:
        print(f"Đã xảy ra lỗi: {e}")

# --- CẤU HÌNH TẠI ĐÂY ---
FILE_GOC = "PDF/copy.pdf"      # Tên file PDF của bạn
FILE_MOI = "PDF/extracted.pdf"     # Tên file sau khi cắt
TRANG_BAT_DAU = 452             # Trang a
TRANG_KET_THUC = 459            # Trang b

# Chạy hàm
cut_pdf(FILE_GOC, FILE_MOI, TRANG_BAT_DAU, TRANG_KET_THUC)