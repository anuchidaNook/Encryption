from Crypto.Cipher import AES
import os
from dotenv import load_dotenv

# โหลดค่าจาก .env
load_dotenv()

# ตรวจสอบค่าจาก .env
SECRET_KEY = os.getenv("SECRET_KEY")
IV = os.getenv("IV")

# ตรวจสอบว่าค่าถูกต้อง
if SECRET_KEY is None or IV is None:
    raise ValueError("❌ SECRET_KEY หรือ IV ไม่พบใน .env กรุณาเพิ่มค่าดังนี้:\nSECRET_KEY=your32bytekey\nIV=your16byteiv")

SECRET_KEY = SECRET_KEY.encode()[:32]  # 32-byte Key
IV = IV.encode()[:16]  # 16-byte IV

print(f"🔑 Key Length: {len(SECRET_KEY)} bytes")
print(f"🔹 IV Length: {len(IV)} bytes")

def encrypt_image(input_file, output_file):
    # ตรวจสอบว่าไฟล์มีอยู่จริง
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"❌ ไม่พบไฟล์: {input_file}")

    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

    with open(input_file, "rb") as f:
        file_data = f.read()

    # เติม Padding ให้ข้อมูลเป็นจำนวนเต็มของ 16 ไบต์
    padding = 16 - (len(file_data) % 16)
    file_data += bytes([padding]) * padding

    encrypted_data = cipher.encrypt(file_data)

    with open(output_file, "wb") as f:
        f.write(encrypted_data)

    print(f"🔐 รูปภาพถูกเข้ารหัสแล้ว: {output_file}")

def decrypt_image(input_file, output_file):
    # ตรวจสอบว่าไฟล์มีอยู่จริง
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"❌ ไม่พบไฟล์: {input_file}")

    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    # ลบ Padding ที่เติมไว้
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"🔓 รูปภาพถูกถอดรหัสแล้ว: {output_file}")

if __name__ == "__main__":
    # ใช้พาธแบบเต็มเพื่อลดข้อผิดพลาด
    base_path = "/home/nb-anuchida/Desktop/encryption-project-test-main/encryption file/"
    input_file = os.path.join(base_path, "exam_01.jpg")
    encrypted_file = os.path.join(base_path, "exam_01_encrypted.bin")
    decrypted_file = os.path.join(base_path, "exam_01_decoded.jpg")

    encrypt_image(input_file, encrypted_file)
    decrypt_image(encrypted_file, decrypted_file)
