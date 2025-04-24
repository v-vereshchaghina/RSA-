import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate a private key.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Extract the public key from the private key.
public_key = private_key.public_key()

# Convert the private key into bytes (без шифрования).
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    backend=default_backend(),
    password=None
)

public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend()
)


# for anything other than the practice exercise
################
def simple_rsa_encrypt(m, publickey):
    # Public_numbers returns a data structure with the 'e' and 'n' parameters.
    # Refactor Является ли переменная 'm' числовым значением
    if isinstance(m, int):
        numbers = publickey.public_numbers()
        # Encryption: (m^e) % n.
        return gmpy2.powmod(m, numbers.e, numbers.n)
    return ValueError(f'{type(m)} No type: integer')


def simple_rsa_decrypt(c, privatekey):
    # Refactor Проверка на правильный тип данных
    if isinstance(c, gmpy2.mpz):
        # Private_numbers returns a data structure with the 'd' and 'n' parameters.
        numbers = privatekey.private_numbers()
        # Дешифрование: (c^d) % n.
        return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)
    return TypeError(f'{type(c)} No type: gmpy2.mpz ')


a = simple_rsa_encrypt(1234, public_key)
print(a)
b = simple_rsa_decrypt(a, private_key)
print(b)

