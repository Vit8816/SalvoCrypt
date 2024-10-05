import math
import string
import base64
import secrets
import numpy as np

chars = string.ascii_letters + string.digits + string.punctuation

class Utils:
    @staticmethod
    def text_to_binary(text):
        if isinstance(text, bytes):
            text = text.decode('utf-8')
        return ''.join(format(ord(c), '08b') for c in text)
    @staticmethod
    def binary_to_text(binary):
        chars = [binary[i:i + 8] for i in range(0, len(binary), 8)]
        return ''.join(chr(int(c, 2)) for c in chars)
    @staticmethod
    def split_into_blocks(data, block_size=64):
        while len(data) % block_size != 0:
            data += '0'
        return [data[i:i + block_size] for i in range(0, len(data), block_size)]
    @staticmethod
    def generate_key_matrix(key):
        key_blocks = Utils.split_into_blocks(Utils.text_to_binary(key))
        return np.array([list(map(int, block)) for block in key_blocks])

class Cipher:
    def __init__(self, const: int):
        self.n = const
        self.key = ""
        self.loaded_key = b""
        const = int(((3 * math.log2(const) + const ** 2) % (const + 5) + math.sqrt(const ** 3 + 7)) % (const ** 3 + 10))
        pow_n = int(((math.log2(const**3 + 1) + const*2) % (const + 7) + (const*5 + 3*const) / 2) % (const**4 + math.log(const + 10)))
        const = self.calc_const(const)
        pow_n = self.calc_pow_n(pow_n)
        self.pow_n = pow_n
        self.const_int = const
        self.const = const.to_bytes(math.ceil(const.bit_length() / 8), 'big').hex()
    def calc_const(self, n):
        const = int((n % n) * n + (math.log2(n) + math.log(n, 2))) + 1
        const = int((((((n % const) * (const % n)) ** 2) / 2) + 2)+self.n)
        return const
    def calc_pow_n(self, pow_n):
        base = (pow_n & (pow_n - 1) + pow_n) + 1
        intermediate = ((pow_n ^ base + (base // 2)) % base) + 2
        pow_n = int(((intermediate * (base ** 2)) + (base % intermediate) + pow_n)-self.n)
        return pow_n
    def generate_key(self, length: int):
        if length < 4096:
            print("Min length of key should be 4096")
            exit()
        self.key = "".join(secrets.choice(chars) for _ in range(length))
        self.load_key()
    def xor(self, text, key):
        return bytes([x ^ y for x, y in zip(text, key)])
    def xor_matrix(self, matrix, key):
        return matrix ^ key
    def set_key(self, key):
        if len(key) < 4096:
            print("Min length of key should be 4096")
            exit()
        self.key = key
        self.load_key()
    def load_key(self):
        if self.key == "":
            print("Please generate or load key")
            exit()
        self.loaded_key = b""
        for c in self.key:
            c = ord(c)
            c = int(((self.pow_n%c)+(self.const_int%c))/2)
            self.loaded_key += c.to_bytes(1, 'big')
        self.loaded_key = self.loaded_key*len(self.key)
        const = int(self.const,16)
        len_key = len(self.key)
        len_key = len_key.to_bytes(math.ceil(len_key.bit_length() / 8), 'big').hex()
        const = const.to_bytes(math.ceil(const.bit_length() / 8), 'big').hex()
        self.const = const*len(self.key)
        self.calc_matrix_key()
    def calc_matrix_key(self):
        mat = 0
        m = self.const_int
        n = self.n
        p = self.pow_n
        key = b""
        for c in self.key:
            k = ord(c)
            mm = (((m*n)+p)%k) + 1
            mat = int(((p+n)/(m+k)))
            key += chr(int((math.log2(mat + 1) + (p**2 % 256) + (n**3 % 256)) % 256)).encode()
        self.matrix_key = Utils.generate_key_matrix(self.xor(self.const.encode(),self.xor(key, self.loaded_key)).decode("utf8", errors="ignore"))
    def enc_matrix(self, text):
        text = Utils.text_to_binary(text)
        text = Utils.split_into_blocks(text)
        text = np.array([list(map(int, block)) for block in text])
        tt = []
        for text_block in text:
            encrypted_block = self.xor_matrix(np.array(text_block), self.matrix_key[0])
            tt.append(''.join(map(str, encrypted_block)))
        text = Utils.binary_to_text(''.join(tt))
        return base64.b64encode(text.encode()).decode()
    def dec_matrix(self, encrypted_text):
        encrypted_text = base64.b64decode(encrypted_text).decode()
        encrypted_binary = Utils.text_to_binary(encrypted_text)
        encrypted_blocks = Utils.split_into_blocks(encrypted_binary)
        encrypted_array = np.array([list(map(int, block)) for block in encrypted_blocks])
        decrypted_blocks = []
        for encrypted_block in encrypted_array:
            decrypted_block = self.xor_matrix(np.array(encrypted_block), self.matrix_key[0])
            decrypted_blocks.append(''.join(map(str, decrypted_block)))
        decrypted_binary = ''.join(decrypted_blocks)
        decrypted_text = Utils.binary_to_text(decrypted_binary)
        return decrypted_text
    def encrypt(self, text: str):
        text = text.encode()
        text = base64.b64encode(text)
        text = text[::-1]
        text = self.xor(text, self.const.encode())
        text = text[::-1]
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = base64.b64encode(self.enc_matrix(text)[::-1].encode())
        return text
    def decrypt(self, text):
        text = base64.b64decode(text).decode()
        text = self.dec_matrix(text[::-1])
        text = text[::-1].encode()
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = self.xor(text, self.const.encode())
        text = text[::-1].decode()
        text = base64.b64decode(text).decode()
        return text
