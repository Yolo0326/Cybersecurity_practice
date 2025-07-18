# 实现协议
来自刘巍然老师的报告google password checkup，参考论文 https://eprint.iacr.org/2019/723.pdf 的section 3.1 ，也即Figure 2中展示的协议，尝试实现该协议（编程语言不限）
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
