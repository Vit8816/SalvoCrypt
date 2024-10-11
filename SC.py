import math
import string
import base64
import secrets
import numpy as np

chars = string.ascii_letters + string.digits + string.punctuation

class Utils:
    @staticmethod
    def text_to_binary(text):
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
        b = int(key_blocks[0], 2)
        for n in range(1, len(key_blocks)):
            kb = int(key_blocks[n], 2)
            b = (b ^ kb) ^ b
        b = [str(format(b, '064b'))]
        return b
    @staticmethod
    def calc_dividends(x, a, b):
        while True:
            a_squared = int(((x*3+(x+3)*2)+b)*0.25)
            b_squared = int(((x*3+(x-3)*2)+a)*0.5)
            if math.gcd(a_squared, b_squared) == 1:
                return a_squared, b_squared
            else:
                x += 1
    @staticmethod
    def elliptic_curve_calc(x, a, b):
        a_squared = int((x*3+(x+b)*2)/b)+1
        b_squared = int((x*3+(x-a)*2)/a)-1
        return a_squared, b_squared

class Cipher:
    def __init__(self, const: int):
        self.n = const
        self.key = ""
        self.loaded_key = b""
        const = int(((3 * math.log2(const) + const ** 2) % (const + 5) + math.sqrt(const ** 3 + 7)) % (const ** 3 + 10))
        pow_n = int(((math.log2(const**3 + 1) + const*2) % (const + 7) + (const*5 + 3*const) / 2) % (const**4 + math.log(const + 10)))
        self.const_a, self.const_b = Utils.calc_dividends(self.n, const, pow_n)
        self.pow_n_a, self.pow_n_b = Utils.calc_dividends(self.n, pow_n, const)
        self.const = self.calc_const(const)
        self.pow_n = self.calc_pow_n(pow_n)
        self.const_int = Utils.calc_dividends(self.n, self.const, self.pow_n)[1]%self.const_b
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
        matrix = np.array(matrix, dtype=int)
        key = np.array(list(map(int, key)), dtype=int)
        return np.bitwise_xor(matrix, key)
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
        for t in self.key:
            c = ord(t)
            c = int((((self.pow_n%c)+(self.const_int%c))+1))
            a,b = Utils.elliptic_curve_calc(self.n, c, self.const_a)
            self.loaded_key += str(a+b+c).encode()
        self.loaded_key = self.loaded_key*len(self.key)
        self.loaded_key = base64.b85encode(self.loaded_key)
        const = int(self.const,16)
        const = const.to_bytes(math.ceil(const.bit_length() / 8), 'big').hex()
        self.const = const.encode()
        self.calc_matrix_key()
    def calc_matrix_key(self):
        mat = 0
        m = self.const_int
        n = self.n
        p = self.pow_n
        key = ""
        for c in self.key:
            k = ord(c)
            mm = (((m*n)+p)%k) + 1
            mat = int(((p+n)/(m+k)))
            key += chr(int((math.log2(mat + 1) + (p**2 % 256) + (n**3 % 256)) % k))
        self.matrix_key = Utils.generate_key_matrix(str(key))
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
    def enc_math(self, text: str):
        rest = ""
        for t in text:
            c = ord(t)
            c = (c*self.const_a)-self.const_b
            c = (c*self.pow_n_a)-self.pow_n_b
            rest += f"{c} "
        return base64.b64encode(rest.encode()).decode()
    def dec_math(self, text: str):
        rest = ""
        text = base64.b64decode(text.encode()).decode()
        for t in text.split(" "):
            if t.strip():
                c = int(t)
                c = (c+self.pow_n_b)/self.pow_n_a
                c = (c+self.const_b)/self.const_a
                rest += chr(int(c))
        return rest
    def encrypt(self, text: str):
        text = self.enc_math(text)
        text = self.enc_matrix(text)
        text = text.encode()
        text = base64.b85encode(text)
        text = text[::-1]
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = base64.b64encode(text).decode()
        return text
    def decrypt(self, text):
        text = base64.b64decode(text).decode()
        text = text[::-1].encode()
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = base64.b85decode(text).decode()
        text = self.dec_matrix(text)
        text = self.dec_math(text)
        return text
