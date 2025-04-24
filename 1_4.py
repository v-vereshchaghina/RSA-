import random
import time
import gmpy2
import itertools
import string
from cryptography.hazmat.primitives.asymmetric import rsa


# Функция шифрования RSA
def rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


# Перебор возможных слов для расшифровки
def brute_force_rsa(ciphertext, public_key):
    start_time = time.time()  # Засечь время начала
    letters = string.ascii_lowercase  # Алфавит a-z
    # Перебор всех возможных комбинаций букв
    for length in range(1, 6): # Максимальная длина слова
        for word in itertools.product(letters, repeat=length):
            guess_word = ''.join(word)  # Слово
            guess_number = int.from_bytes(guess_word.encode(), 'big')  # Преобразование в число
            if rsa_encrypt(guess_number, public_key) == ciphertext: # нашли(подобрали) слово
                end_time = time.time()
                return guess_word, end_time - start_time
    return None  # Если ничего не найдено


# Генерация RSA-ключа
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024  # размер ключа
)
public_key = private_key.public_key() # Получаем открытый ключ
messages = {1: 'dog', 2: 'cat', 3: 'bird', } # Словарь
for message in messages.values():
    original_number = int.from_bytes(message.encode(), 'big')  # Перевод в байты(0,1)
# шифрование
    ciphertext = rsa_encrypt(original_number, public_key)
# Взлом
    cracked_word = brute_force_rsa(ciphertext, public_key)
# Результат
    print(f"Зашифрованное слово: {message}")
    print(f"Шифртекст: {ciphertext}")
    print(f"Взломанное слово: {cracked_word}")
