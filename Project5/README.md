# SM2的软件实现及其优化
## SM2基本介绍
SM2是基于椭圆曲线密码学(ECC)的非对称加密，其签名速度与密钥生成速度都快于RSA。ECC 256位（SM2采用的就是ECC 256位的一种）安全强度比RSA 2048位高，但运算速度快于RSA。
- 优势
1. 高效性：SM2的安全性基于椭圆曲线数学问题，能够在较短的密钥长度下实现与RSA相当的安全性。使用256位的椭圆曲线SM2密钥，其安全性相当于3072位的RSA密钥，这使得SM2在处理同样复杂度的加密任务时速度更快，特别适合在资源受限的设备上运行。  
2. 随机性：SM2加密在每次加密时都会生成一个新的随机数，这使得每次加密的结果都不同，大大增加了对抗重放攻击的难度。
3. 本土化标准：SM2是中国自主开发的国家标准，加密算法经过了严格的数学论证和实战测试，适用于各种本地化的应用场景。  
## SM2原理
- SM2密钥对的生成  
1. 选定椭圆曲线参数（a,b）和基点 G
2. 随机生成私钥d，满足1 ≤ d ≤ n-1
3. 计算公钥Q=dG
- SM2加密流程
1. 计算椭圆曲线点P1=k*G，C1=P1
2. 计算S=k*Q，得到点S=(x2, y2)，使用密钥派生函数KDF计算K= KDF(x2||y2, len(M))
3. 计算密文C2= M⊕K（逐比特异或）
4. 计算C3=Hash(x2||M||y2)，其中Hash通常是SM3  
5. 最后发送的密文是(C1,C2,C3)（在新标准中发送的是(C1,C3,C2)）
- SM2解密流程
1. 验证C1的有效性，检查是否满足椭圆曲线方程，是否为无穷远点
2. 计算共享密钥S=dC1=(x2', y2')，与加密时的共享密钥一致，使用相同的KDF计算K'=KDF(x2'||y2',len(C2))
3. 计算明文：M'=C2⊕K'
4. 重新计算哈希值C3'= Hash(x2'||M'||y2')
5. 比较C3与C3'，若二者相等，则解密成功，输出明文M'
## SM2代码实现
- SM2算法的椭圆曲线参数
```Python
# SM2的椭圆曲线参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
```
- SM2类  
1. 在类中定义模逆的函数，椭圆曲线点加、点乘计算等
```Python
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
```
2. 定义密钥派生函数(KDF)
```Python
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
```
3. SM2加解密函数  
根据加解密流程所示，分别计算C1 C2 C3
```Python
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
```
4. SM2签名及验证
```Python
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
```
