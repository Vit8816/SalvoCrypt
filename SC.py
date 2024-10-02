import math
import random
import string
import base64
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
        pow_n = int((const&const-1)%const)+ const
        const = int((const^pow_n + int(pow_n/2))%pow_n)
        const = int(const%pow_n)
        const = int(math.pow(math.log2(const), math.log2(pow_n)))
        pow_n = int((const*(math.pow(pow_n,2)))+(pow_n%const)+const)
        const = int(((pow_n%const)*pow_n)+(math.log2(pow_n)+math.log(const)))
        const = int((((pow_n%const)*(const%pow_n))**2)/2)
        self.pow_n = pow_n
        self.const_int = const
        self.const = const.to_bytes(math.ceil(const.bit_length() / 8), 'big').hex()
    def calc_const(self, n):
        const = int((n % n) * n + (math.log2(n) + math.log(n, 2)))+1
        const = int((((n % const) * (const % n)) ** 2) / 2)+2
        return const
    def calc_pow_n(self, const):
        base = (const & (const - 1) + const)+1
        intermediate = ((const ^ base + (base // 2)) % base)+2
        pow_n = int((intermediate * (base ** 2)) + (base % intermediate) + const)
        return pow_n
    def generate_key(self, length: int):
        if length < 4096:
            print("Min length of key should be 4096")
            exit()
        self.key = "".join(random.choice(chars) for _ in range(length))
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
            mat = int(((m * n) % mm + (p % (m-p)) * (n % mm)) / 3)
            key += chr(int((((m * n) % k + (p % mm)) / 2)+mat)).encode()
        self.matrix_key = Utils.generate_key_matrix(self.xor(key, self.loaded_key).decode("utf8", errors="ignore"))
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
        text = text.hex().encode()
        text = text[::-1]
        text = self.xor(text, self.const.encode())
        text = text[::-1]
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = self.enc_matrix(text)[::-1].encode().hex()
        return text
    def decrypt(self, text):
        text = bytes.fromhex(text).decode()
        text = self.dec_matrix(text[::-1])
        text = text[::-1].encode()
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = self.xor(text, self.const.encode())
        text = text[::-1].decode()
        text = bytes.fromhex(text).decode()
        return text
