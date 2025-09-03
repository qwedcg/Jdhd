import os
import zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 🔑 إعداد المفتاح AES (باسورد = "0" محول إلى 16 بايت)
KEY = b"0".ljust(16, b"\0")  # AES-128-ECB

# 📂 ملف الـ ZIP الأول اللي بيه الأسماء
ZIP_FILE = "Decrypt.zip"
EXTRACT_DIR = "decrypt_files"
OUTPUT_DIR = "encrypted_files"

# تأكد من وجود مجلد الإخراج
os.makedirs(OUTPUT_DIR, exist_ok=True)

# استخراج الملفات من Decrypt.zip
with zipfile.ZipFile(ZIP_FILE, 'r') as zip_ref:
    zip_ref.extractall(EXTRACT_DIR)

# جلب أسماء الملفات المستخرجة
files = os.listdir(EXTRACT_DIR)

print("=== القائمة ===")
for i, fname in enumerate(files, 1):
    print(f"{i}. {fname}")

choice = input("اختر رقم: ")

try:
    idx = int(choice) - 1
    if idx < 0 or idx >= len(files):
        raise ValueError("خيار غير صالح")

    selected_file = files[idx]
    file_path = os.path.join(EXTRACT_DIR, selected_file)

    # قراءة محتوى الملف
    with open(file_path, "rb") as f:
        data = f.read()

    # تشفير AES-128-ECB
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data, AES.block_size))

    # حفظ الملف المشفر بنفس الاسم + .cipher
    out_file = os.path.join(OUTPUT_DIR, selected_file + ".cipher")
    with open(out_file, "wb") as f:
        f.write(encrypted)

    print(f"✅ تم إنشاء الملف المشفر: {out_file}")

except Exception as e:
    print("خطأ:", e)