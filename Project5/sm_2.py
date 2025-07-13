import random
import hashlib
import binascii

# SM2的椭圆曲线参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)

    # 模逆算法(扩展欧几里得)
    def _mod_inverse(self, a, p):
        old_r, r = a, p
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        return old_s % p

    # 椭圆曲线点加
    def _point_add(self, P, Q):
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 + y2) % self.p == 0:
            return (0, 0)
        if P == Q:
            l = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p) % self.p
        else:
            l = (y2 - y1) * self._mod_inverse(x2 - x1, self.p) % self.p

        x3 = (l * l - x1 - x2) % self.p
        y3 = (l * (x1 - x3) - y1) % self.p
        return (x3, y3)

    # 椭圆曲线点乘
    def _point_mul(self, k, P):
        result = (0, 0)
        while k > 0:
            if k & 1:
                result = self._point_add(result, P)
            P = self._point_add(P, P)
            k >>= 1
        return result

    # SM2密钥对生成
    def generate_keypair(self):
        private_key = random.randint(1, self.n - 1)
        public_key = self._point_mul(private_key, self.G)
        return private_key, public_key

    # 密钥派生函数(基于SM3)
    def _kdf(self, Z, klen):
        ct = 0x00000001
        rcnt = (klen + 31) // 32
        output = b''
        for i in range(rcnt):
            ct_bytes = ct.to_bytes(4, 'big')
            hash_input = Z + ct_bytes
            sm3 = hashlib.new('sm3')
            sm3.update(hash_input)
            output += sm3.digest()
            ct += 1
        return output[:klen]

    # SM2加密
    def encrypt(self, public_key, msg):
        if isinstance(msg, str):
            msg = msg.encode()
        klen = len(msg)
        k = random.randint(1, self.n - 1)

        # 计算C1
        C1 = self._point_mul(k, self.G)
        C1_bytes = b'\x04' + C1[0].to_bytes(32, 'big') + C1[1].to_bytes(32, 'big')

        # 计算S
        S = self._point_mul(k, public_key)
        S_bytes = b'\x04' + S[0].to_bytes(32, 'big') + S[1].to_bytes(32, 'big')

        # 计算派生密钥
        Z = S_bytes
        t = self._kdf(Z, klen)
        if all(b == 0 for b in t):
            raise ValueError("KDF derived key is zero")

        # 计算密文C2
        C2 = bytes([m ^ t_i for m, t_i in zip(msg, t)])

        # 计算C3
        sm3 = hashlib.new('sm3')
        sm3.update(bytes([x for x in msg]))
        sm3.update(Z)
        C3 = sm3.digest()

        return C1_bytes + C3 + C2

    # SM2解密
    def decrypt(self, private_key, ciphertext):
        # 解析密文
        if ciphertext[0] != 0x04:
            raise ValueError("Invalid ciphertext format")
        C1 = (int.from_bytes(ciphertext[1:33], 'big'),
              int.from_bytes(ciphertext[33:65], 'big'))
        C3 = ciphertext[65:97]
        C2 = ciphertext[97:]
        klen = len(C2)

        # 计算椭圆曲线点S
        S = self._point_mul(private_key, C1)
        S_bytes = b'\x04' + S[0].to_bytes(32, 'big') + S[1].to_bytes(32, 'big')

        # 计算派生密钥
        Z = S_bytes
        t = self._kdf(Z, klen)
        if all(b == 0 for b in t):
            raise ValueError("KDF derived key is zero")

        # 解密消息
        msg = bytes([c ^ t_i for c, t_i in zip(C2, t)])

        # 验证C3
        sm3 = hashlib.new('sm3')
        sm3.update(msg)
        sm3.update(Z)
        u = sm3.digest()
        if u != C3:
            raise ValueError("Hash verification failed")

        return msg

    # SM2签名
    def sign(self, private_key, msg, ID=b'1234567812345678'):
        if isinstance(msg, str):
            msg = msg.encode()

        # 计算ZA
        entl = len(ID) * 8
        ENTL = entl.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        Gx_bytes = self.G[0].to_bytes(32, 'big')
        Gy_bytes = self.G[1].to_bytes(32, 'big')
        public_key = self._point_mul(private_key, self.G)
        Px_bytes = public_key[0].to_bytes(32, 'big')
        Py_bytes = public_key[1].to_bytes(32, 'big')

        sm3_za = hashlib.new('sm3')
        sm3_za.update(ENTL + ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + Px_bytes + Py_bytes)
        ZA = sm3_za.digest()

        # 计算e = Hv(ZA ∥ M)
        sm3_e = hashlib.new('sm3')
        sm3_e.update(ZA + msg)
        e = int.from_bytes(sm3_e.digest(), 'big')

        # 生成签名
        while True:
            k = random.randint(1, self.n - 1)
            x1, y1 = self._point_mul(k, self.G)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            s = (self._mod_inverse(1 + private_key, self.n) * (k - r * private_key)) % self.n
            if s != 0:
                break

        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    # 签名验证
    def verify(self, public_key, msg, signature, ID=b'1234567812345678'):
        if isinstance(msg, str):
            msg = msg.encode()

        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:], 'big')
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        # 计算ZA
        entl = len(ID) * 8
        ENTL = entl.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        Gx_bytes = self.G[0].to_bytes(32, 'big')
        Gy_bytes = self.G[1].to_bytes(32, 'big')
        Px_bytes = public_key[0].to_bytes(32, 'big')
        Py_bytes = public_key[1].to_bytes(32, 'big')

        sm3_za = hashlib.new('sm3')
        sm3_za.update(ENTL + ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + Px_bytes + Py_bytes)
        ZA = sm3_za.digest()
        # 计算e
        sm3_e = hashlib.new('sm3')
        sm3_e.update(ZA + msg)
        e = int.from_bytes(sm3_e.digest(), 'big')

        t = (r + s) % self.n
        if t == 0:
            return False

        # 计算椭圆曲线点
        point1 = self._point_mul(s, self.G)
        point2 = self._point_mul(t, public_key)
        x1, y1 = self._point_add(point1, point2)

        R = (e + x1) % self.n
        return R == r

    def serialize_public_key(self, public_key):
        return b'\x04' + public_key[0].to_bytes(32, 'big') + public_key[1].to_bytes(32, 'big')


# 测试
if __name__ == "__main__":
    sm2 = SM2()

    # 密钥生成
    private_key, public_key = sm2.generate_keypair()

    public_key_bytes = sm2.serialize_public_key(public_key)
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: {binascii.hexlify(public_key_bytes).decode()}")

    # 加密解密
    message = "Hello World!"
    print("原始消息:", message)
    ciphertext = sm2.encrypt(public_key, message)
    print("加密结果:", binascii.hexlify(ciphertext).decode())
    decrypted = sm2.decrypt(private_key, ciphertext)
    print("解密结果:", decrypted.decode())

    # 签名验证
    signature = sm2.sign(private_key, message)
    print("签名结果:", binascii.hexlify(signature).decode())

    is_valid = sm2.verify(public_key, message, signature)
    print("验证结果:", "成功" if is_valid else "失败")