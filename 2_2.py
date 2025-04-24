import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def encrypt(data, aad, key, key2=None): # Шифрование
    size = 4096 # Размер блока данных
    ciphertexts = []
    nonces = []
    if key2:
        aesgcm = ChaCha20Poly1305(key2) # Если передан key2, используется ChaCha20
    else:
        aesgcm = AESGCM(key) # Иначе используется AES-GCM
    # Шифрование данных по частям
    for i in range(0, len(data), size):
        chunk = data[i:i + size]
        nonce = os.urandom(12)  # Генерация нового nonce для каждого куска
        ct = aesgcm.encrypt(nonce, chunk, aad) # Шифрование блока chunk, с этим nonce, и доп. данными aad
        ciphertexts.append(ct)
        nonces.append(nonce) # Сохранение зашифрованного блока и соответствующего nonce
    return ciphertexts, nonces


# Расшифровка
def decrypt(ciphertexts, nonces, aad, key, key2=None):
    if key2:
        aesgcm = ChaCha20Poly1305(key2)
    else:
        aesgcm = AESGCM(key)
    decrypted_chunks = []
    # Расшифровка каждого куска
    for i, ct in enumerate(ciphertexts):
        chunk = aesgcm.decrypt(nonces[i], ct, aad)
        decrypted_chunks.append(chunk)
    # Объединить все расшифрованные куски
    return b''.join(decrypted_chunks)


# Пример использования
data = b"A very large secret document that needs to be encrypted" * 10000  # Большой объем данных, строка повторяется 10000 раз
aad = b"authenticated but unencrypted data"  # Дополнительные данные - участвуют в проверке подлинности, но не шифруются
key = AESGCM.generate_key(bit_length=128)
key2 = ChaCha20Poly1305.generate_key()
# Шифрование
ciphertexts, nonces = encrypt(data, aad, key)
# Шифрование ChaCha20Poly1305
# ciphertexts, nonces = encrypt(data, aad, key, key2=key2)

# Расшифровка
decrypted_data = decrypt(ciphertexts, nonces, aad, key)
# Расшифровка ChaCha20Poly1305
# decrypted_data = decrypt(ciphertexts, nonces, aad, key, key2=key2)

# Проверка
if decrypted_data == data:
    print("Test = 'Ok'")
