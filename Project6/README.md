# 实现协议(Python版本)
来自刘巍然老师的报告google password checkup，参考论文 https://eprint.iacr.org/2019/723.pdf 的section 3.1 ，也即Figure 2中展示的协议，尝试实现该协议
## 协议主要流程
- Setup  
1. P1随机选择私钥k1∈Z_|G|，P2随机选择私钥k2∈Z_|G|
2. P2生成加法同态加密的密钥对：(pk,sk)←AGen(λ)，并将公钥pk发送给P1
- Round 1(P1)
1. 对每个v_i∈V，计算H(v_i)^k1
2. 打乱顺序，发送集合{H(v_i)^k1}^m1给P2
- Round 2(P2)  
1. 对收到的每个H(v_i)^k1，计算(H(v_i)^k1)^k2=H(v_i)^(k1k2)
2. 打乱顺序，发送集合Z={H(v_i)^(k1k2)}^m1给P1
3. 对于每个(w_j,t_j)∈W，计算H(w_j)^k2，加密权重AEnc(t_j)
4. 打乱顺序，发送集合{H(w_j)^k2，AEnc(t_j)}^m2给P1
- Round 3(P1)  
1. 对于收到的每个(H(w_j)^k2，AEnc(t_j))，计算(H(w_j)^k2)^k1=H(w_j)^(k1k2)
2. 定义交集索引集J={j:H(w_j)^(k1k2)∈Z}
3. 同态求和：Aenc(pk,S_J)=ASum({AEnc(t_j)})
4. 使用ARefresh重随机化密文
5. 发送AEnc(pk,S_J)给P2
- 输出  
P2用私钥sk解密，得到交集和S_J
## 代码实现
主要思路：协议有两方参与，故分别定义P1和P2的类，类中包括各自需要的功能  
### P1
在P1的类中，首先对必要的参数进行初始化，并随机选择私钥k1。  
round1,round2,round3函数分别对应协议流程中123步中P1需要完成的操作，包括计算相应的哈希值，打乱顺序等等
```Python
class ProtocolPart_1:
    def __init__(self, set_V):
        self.V = set_V
        self.k1 = None
        self.p = None
        self.q = None
        self.g = None
        self.pk = None
        self.A_shuffled = None
        self.Z = None
        self.set_W2 = None
        self.intersection_sum_enc = None

    def receive_public_info(self, p, q, g, pk):
        self.p = p
        self.q = q
        self.g = g
        self.pk = pk
        self.k1 = random.randint(1, q - 1)  # 选择私钥k1

    def round1(self):
        A = []
        for v in self.V:
            h_val = self.hash_to_group(v)
            A_i = pow(h_val, self.k1, self.p)
            A.append(A_i)
        random.shuffle(A)  # 打乱顺序
        self.A_shuffled = A
        return A

    def receive_round2(self, Z, set_W2):
        self.Z = set(Z)  # 转换为集合便于快速查找
        self.set_W2 = set_W2  # [(H(w_j)^k2, AEnc(t_j)]

    def round3(self):
        E_list = []
        enc_list = []
        for item in self.set_W2:
            C_j, enc_tj = item
            E_j = pow(C_j, self.k1, self.p)  # 计算H(w_j)^(k1*k2)
            E_list.append(E_j)
            enc_list.append(enc_tj)

        # 计算交集索引
        J_indices = [i for i, E_j in enumerate(E_list) if E_j in self.Z]

        # 同态求和
        if not J_indices:
            sum_enc = self.pk.encrypt(0)
        else:
            sum_enc = enc_list[J_indices[0]]
            for idx in J_indices[1:]:
                sum_enc += enc_list[idx]

        # 刷新密文：添加加密的0
        refreshed_enc = sum_enc + self.pk.encrypt(0)
        self.intersection_sum_enc = refreshed_enc
        return refreshed_enc

    def hash_to_group(self, s):
        """ 哈希字符串到群元素 H(s) = g^{hash(s) mod q} mod p """
        h = hashlib.sha256(s.encode()).digest()
        x = int.from_bytes(h, 'big') % self.q
        return pow(self.g, x, self.p)
```
### P2
P2的类中包括初始化的参数，生成同态加密的密钥对，并对P1发送的集合进行处理
```Python
class ProtocolPart_2:
    def __init__(self, set_W):
        self.W = set_W
        self.k2 = None
        self.p = None
        self.q = None
        self.g = None
        self.public_key = None
        self.private_key = None
        self.A_received = None
        self.intersection_sum = None

    def generate_public_info(self, q_bits=256):
        # 生成安全素数 p = 2q + 1
        self.q = gmpy2.next_prime(random.getrandbits(q_bits))
        self.p = 2 * self.q + 1
        while not gmpy2.is_prime(self.p):
            self.q = gmpy2.next_prime(self.q)
            self.p = 2 * self.q + 1
        self.p = int(self.p)
        self.q = int(self.q)

        # 生成群生成元 g
        while True:
            h = random.randint(2, self.p - 2)
            self.g = pow(h, 2, self.p)
            if self.g != 1:
                break

        # 生成Paillier密钥对
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        return self.p, self.q, self.g, self.public_key

    def receive_round1(self, A):
        self.A_received = A
        self.k2 = random.randint(1, self.q - 1)  # 选择私钥k2

    def round2(self):
        # 处理P1的集合：计算 Z = [H(v_i)^(k1*k2)]
        Z = [pow(a, self.k2, self.p) for a in self.A_received]
        random.shuffle(Z)

        # 处理自身集合：计算 [(H(w_j)^k2, AEnc(t_j))]
        set_W2 = []
        for w, t in self.W:
            h_val = self.hash_to_group(w)
            C_j = pow(h_val, self.k2, self.p)
            enc_tj = self.public_key.encrypt(t)
            set_W2.append((C_j, enc_tj))
        random.shuffle(set_W2)

        return Z, set_W2

    def receive_round3(self, encrypted_sum):
        self.intersection_sum = self.private_key.decrypt(encrypted_sum)
        return self.intersection_sum

    def hash_to_group(self, s):
        """ 哈希字符串到群元素 H(s) = g^{hash(s) mod q} mod p """
        h = hashlib.sha256(s.encode()).digest()
        x = int.from_bytes(h, 'big') % self.q
        return pow(self.g, x, self.p)
```
