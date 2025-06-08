import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from tkinter import Tk
from tkinter.filedialog import askopenfilename

# Функция для шифрования в режиме GCM
def aes_gcm_encrypt(key, plaintext):
    nonce = get_random_bytes(12)  # Генерация случайного nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag  # Конкатенация nonce, ciphertext и tag

def aes_gcm_decrypt(key, ciphertext):
    nonce = ciphertext[:12]
    tag = ciphertext[-16:]  # Извлечение tag
    ciphertext = ciphertext[12:-16]  # Извлечение ciphertext
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def select_file():
    root = Tk()
    root.withdraw()  # Скрываем основное окно
    file_path = askopenfilename()  # Открываем диалог выбора файла
    root.destroy()  # Закрываем окно после выбора файла
    return file_path


def main():
    input_path = select_file()
    if not input_path:
        print("Файл не выбран.")
        return
      
    action = input("Выберите действие (encrypt/decrypt): ").strip().lower()
    key_input = input("Введите ключ (4-16 символов): ").strip()
  
    if len(key_input) < 4 or len(key_input) > 16:
        print("Ключ должен быть длиной от 4 до 16 символов.")
        return
    for symbol in key_input:
        if ord(symbol) > 0xff:
            print("Ключ должен содержать только латинские буквы и цифры.")
            return
          
    # Генерация ключа фиксированной длины с помощью SHA-256
    key_hash = SHA256.new(key_input.encode('utf-8')).digest()
  
    if action == 'encrypt':
        print("Начинаем шифрование...")
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
                print(f"Читаем файл: {input_path} ({len(data)} байт)")
            start_time = time.time()  # Время начала шифрования
            encrypted_data = aes_gcm_encrypt(key_hash, data)
            end_time = time.time()  # Время окончания шифрования
            out_path = os.path.join(os.path.dirname(input_path), 'crypted_' + os.path.basename(input_path))

            with open(out_path, 'xb') as ff:
                ff.write(encrypted_data)
            elapsed_time = end_time - start_time
            speed = len(data) / elapsed_time  # Скорость в байтах в секунду
            print(f'Файл успешно зашифрован и сохранен как {out_path}')
            print(f'Время шифрования: {elapsed_time:.2f} секунд')
            print(f'Скорость шифрования: {speed:.2f} байт/сек')
          
        except Exception as e:
            print(f'Ошибка при шифровании: {e}')
          
    elif action == 'decrypt':
        print("Начинаем расшифровку...")
      
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
                print(f"Читаем файл: {input_path} ({len(data)} байт)")
            start_time = time.time()  # Время начала расшифровки
            decrypted_data = aes_gcm_decrypt(key_hash, data)
            end_time = time.time()  # Время окончания расшифровки
            out_path = os.path.join(os.path.dirname(input_path), 'decrypted_' + os.path.basename(input_path))
            
          with open(out_path, 'xb') as ff:
                ff.write(decrypted_data)
            elapsed_time = end_time - start_time
            speed = len(data) / elapsed_time  # Скорость в байтах в секунду
            print(f'Файл успешно расшифрован и сохранен как {out_path}')
            print(f'Время расшифровки: {elapsed_time:.2f} секунд')
            print(f'Скорость расшифровки: {speed:.2f} байт/сек')
        
        except Exception as e:
            print(f'Ошибка при расшифровке: {e}')
    
    else:
        print("Неверное действие. Пожалуйста, введите 'encrypt' или 'decrypt'.")
if __name__ == "__main__":
    main()
