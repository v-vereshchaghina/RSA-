import gmpy2
import itertools
import string
import random
from cryptography.hazmat.primitives.asymmetric import rsa


# Функция шифрования RSA
def rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


# Перебор возможных слов для расшифровки
def brute_force_rsa(ciphertext, public_key):
    letters = string.ascii_lowercase  # Алфавит a-z
    # Перебор всех возможных комбинаций букв
    for length in range(1, 5): # Длина слова
        for word in itertools.product(letters, repeat=length):
            guess_word = ''.join(word)  # Слово
            guess_number = int.from_bytes(guess_word.encode(), 'big')  # Преобразование слова в число
            if rsa_encrypt(guess_number, public_key) == ciphertext: # Сравнение шифртекста с результатом шифрования
                return guess_word # Если найдено
    return None  # Если ничего не найдено


# Генерация RSA-ключа
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024  # размер ключа
)
public_key = private_key.public_key()
# Получение открытого ключа из закрытого
length = random.randint(1, 4)  # Длина от 1 до 4 букв
message = input('слово')

# Преобразование слова в число
original_number = int.from_bytes(message.encode(), 'big') # Перевод в байты
# Шифрование числа
ciphertext = rsa_encrypt(original_number, public_key)
# Взлом
cracked_word = brute_force_rsa(ciphertext, public_key)
# Результат
print(f"Зашифрованное слово: {message}")
print(f"Шифртекст: {ciphertext}")
print(f"Взломанное слово: {cracked_word}")
