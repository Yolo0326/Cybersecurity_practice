import random
import hashlib
from phe import paillier
import gmpy2
import time


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
        # 计算 Z = [H(v_i)^(k1*k2)]
        Z = [pow(a, self.k2, self.p) for a in self.A_received]
        random.shuffle(Z)

        # 计算 [(H(w_j)^k2, AEnc(t_j))]
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


# test
if __name__ == "__main__":

    set_V = ["SDU", "PKU", "THU", "SEU"]
    set_W = [("WHU", 10), ("PKU", 20), ("NJU", 30), ("SDU", 40)]

    # 初始化参与方
    P1 = ProtocolPart_1(set_V)
    P2 = ProtocolPart_2(set_W)

    # P2生成公共参数并发送给P1
    p, q, g, pk = P2.generate_public_info(q_bits=256)
    P1.receive_public_info(p, q, g, pk)

    # Round 1
    A = P1.round1()
    P2.receive_round1(A)

    # Round 2
    Z, set_W2 = P2.round2()
    P1.receive_round2(Z, set_W2)

    # Round 3
    encrypted_sum = P1.round3()
    intersection_sum = P2.receive_round3(encrypted_sum)

    # 输出结果
    print("set_V=",set_V)
    print("set_W=",set_W)
    print(f"Output: {intersection_sum}")