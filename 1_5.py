import gmpy2
from cryptography.hazmat.primitives.asymmetric import rsa


# Функции для перевода между int и bytes
def int_to_bytes(i):
    i = int(i)  # Преобразование gmpy2 числа в обычный int
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


# Функция шифрования RSA
def rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)


# Функция дешифрования RSA
def rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)


# Два исходных числа
num1 = 8
num2 = 3
# Генерация ключей RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
public_key = private_key.public_key()
# Шифрование чисел
ciphertext1 = rsa_encrypt(num1, public_key)
ciphertext2 = rsa_encrypt(num2, public_key)
n1 = int_to_bytes(ciphertext1)
n2 = int_to_bytes(ciphertext2)
# Умножение зашифрованные числа
ciphertext_result = bytes_to_int(n1) * bytes_to_int(n2)
# Дешифрование
decrypted_result = rsa_decrypt(ciphertext_result, private_key)
# Вывод результатов
print(f"Число 1: {num1}")
print(f"Число 2: {num2}")
print(f"Зашифрованное число 1: {n1}")
print(f"Зашифрованное число 2: {n2}")
print(f"Произведение зашифрованных чисел: {ciphertext_result}")
print(f"Расшифрованный результат: {decrypted_result}")
print(f"Ожидаемый результат: {num1 * num2}")
