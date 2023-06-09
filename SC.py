import math
import random
import string

chars = string.ascii_letters + string.digits + string.punctuation

class Cipher:
    def __init__(self, const: int):
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
    def generate_key(self, length: int):
        if length < 4096:
            print("Min length of key should be 4096")
            exit()
        self.key = "".join(random.choice(chars) for _ in range(length))
        self.load_key()
    def xor(self, text, key):
        return bytes([x ^ y for x, y in zip(text, key)])
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
    def encrypt(self, text: str):
        text = text.encode()
        text = text.hex().encode()
        text = text[::-1]
        text = self.xor(text, self.const.encode())
        text = text[::-1]
        text = self.xor(text, self.loaded_key)
        text = text[::-1].hex()
        return text
    def decrypt(self, text):
        text = bytes.fromhex(text).decode()
        text = text[::-1].encode()
        text = self.xor(text, self.loaded_key)
        text = text[::-1]
        text = self.xor(text, self.const.encode())
        text = text[::-1].decode(errors="ignore")
        text = bytes.fromhex(text).decode()
        return text

cip = Cipher(3)
cip.generate_key(4096)
clear = "Ciao, questo testo è una prova del cifrario"
enc = cip.encrypt(clear)
print(enc)
dec = cip.decrypt(enc)
print(dec)
