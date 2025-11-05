from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import sys

BLOCK_SIZE_AES = 16
BLOCK_SIZE_DES = 8


def normalize_input_to_bytes(user_input: str) -> bytes:
    s = user_input.strip()
    if len(s) >= 2 and all(c in '0123456789abcdefABCDEF' for c in s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except Exception:
            pass
    return s.encode('utf-8')


def adjust_key(key: bytes, required_len: int) -> bytes:
    if len(key) == required_len:
        return key
    if len(key) < required_len:
        extra = get_random_bytes(required_len - len(key))
        return key + extra
    # más larga -> truncar
    return key[:required_len]


def make_3des_key_parity(key_bytes: bytes) -> bytes:
    kb = bytearray(key_bytes)
    for i in range(len(kb)):
        b = kb[i]
        ones = bin(b).count('1')
        # queremos paridad impar -> si ones es par, flip LSB
        if ones % 2 == 0:
            kb[i] = b ^ 1
    return bytes(kb)


# --- Funciones para DES ---
# Encriptar
def des_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE_DES))
    return ct

# Desencriptar
def des_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE_DES)
    return pt


# --- Funciones para AES-256 ---
# Encriptar
def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE_AES))
    return ct

# Desencriptar
def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE_AES)
    return pt


# --- Funciones para 3DES ---
# Encriptar
def des3_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE_DES))
    return ct

# Desencriptar
def des3_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE_DES)
    return pt


def input_with_prompt(prompt: str) -> str:
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print('\nInterrumpido por el usuario')
        sys.exit(1)


def prepare_iv(user_iv: bytes, required_len: int) -> bytes:
    if len(user_iv) == required_len:
        return user_iv
    if len(user_iv) < required_len:
        extra = get_random_bytes(required_len - len(user_iv))
        return user_iv + extra
    return user_iv[:required_len]


def main():
    print('--- CIFRADO Y DESCIFRADO: DES, 3DES, AES-256 (CBC) ---')
    print()

    # Texto a cifrar
    texto = input_with_prompt('Ingrese el texto a cifrar: ')
    plaintext = texto.encode('utf-8')

    # --- DES ---
    print('\n--- DES (bloque 8 bytes, clave 8 bytes) ---')
    des_key_in = normalize_input_to_bytes(input_with_prompt('Ingrese key para DES: '))
    des_iv_in = normalize_input_to_bytes(input_with_prompt('Ingrese IV para DES: '))

    des_key = adjust_key(des_key_in, 8)
    des_iv = prepare_iv(des_iv_in, 8)

    print(f'Clave DES final (hex): {des_key.hex()}')
    print(f'IV DES final (hex): {des_iv.hex()}')

    des_ct = des_encrypt(des_key, des_iv, plaintext)
    print(f'Texto cifrado DES (base64): {base64.b64encode(des_ct).decode()}')
    des_pt = des_decrypt(des_key, des_iv, des_ct)
    print(f'Texto descifrado DES: {des_pt.decode("utf-8")}' )

    # --- 3DES ---
    print('\n--- 3DES (bloque 8 bytes, clave 24 bytes preferible) ---')
    des3_key_in = normalize_input_to_bytes(input_with_prompt('Ingrese key para 3DES: '))
    des3_iv_in = normalize_input_to_bytes(input_with_prompt('Ingrese IV para 3DES: '))

    # Normalizamos a 24 bytes (si el usuario quiere 16/24, lo truncamos o completamos a 24)
    des3_key_raw = adjust_key(des3_key_in, 24)
    # Ajustar bits de paridad por DES (odd parity) para evitar error de clave inválida
    des3_key = make_3des_key_parity(des3_key_raw)
    des3_iv = prepare_iv(des3_iv_in, 8)

    print(f'Clave 3DES final (hex): {des3_key.hex()}')
    print(f'IV 3DES final (hex): {des3_iv.hex()}')

    # Intentar cifrar/descifrar 3DES
    try:
        des3_ct = des3_encrypt(des3_key, des3_iv, plaintext)
        print(f'Texto cifrado 3DES (base64): {base64.b64encode(des3_ct).decode()}')
        des3_pt = des3_decrypt(des3_key, des3_iv, des3_ct)
        print(f'Texto descifrado 3DES: {des3_pt.decode("utf-8")}')
    except ValueError as e:
        print('Error al inicializar 3DES con la clave generada:', e)
        print('Intentando regenerar bytes aleatorios para producir una clave válida...')
        # Intentaremos generar hasta 10 claves alternadas cambiando los bytes extras
        success = False
        for attempt in range(10):
            alt_raw = des3_key_raw[:8] + get_random_bytes(16)  # conservar los primeros 8 bytes de la clave original
            alt_key = make_3des_key_parity(alt_raw)
            try:
                des3_ct = des3_encrypt(alt_key, des3_iv, plaintext)
                des3_pt = des3_decrypt(alt_key, des3_iv, des3_ct)
                print(f'Clave 3DES alternativa válida encontrada (hex): {alt_key.hex()}')
                print(f'Texto cifrado 3DES (base64): {base64.b64encode(des3_ct).decode()}')
                print(f'Texto descifrado 3DES: {des3_pt.decode("utf-8")}')
                success = True
                break
            except Exception:
                continue
        if not success:
            print('No fue posible generar una clave 3DES válida tras varios intentos.')

    # --- AES-256 ---
    print('\n--- AES-256 (bloque 16 bytes, clave 32 bytes) ---')
    aes_key_in = normalize_input_to_bytes(input_with_prompt('Ingrese key para AES-256: '))
    aes_iv_in = normalize_input_to_bytes(input_with_prompt('Ingrese IV para AES-256: '))

    aes_key = adjust_key(aes_key_in, 32)
    aes_iv = prepare_iv(aes_iv_in, 16)

    print(f'Clave AES-256 final (hex): {aes_key.hex()}')
    print(f'IV AES-256 final (hex): {aes_iv.hex()}')

    aes_ct = aes_encrypt(aes_key, aes_iv, plaintext)
    print(f'Texto cifrado AES-256 (base64): {base64.b64encode(aes_ct).decode()}')
    aes_pt = aes_decrypt(aes_key, aes_iv, aes_ct)
    print(f'Texto descifrado AES-256: {aes_pt.decode("utf-8")}')


if __name__ == '__main__':
    main()
