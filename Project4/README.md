# SM3的软件实现及优化
## SM3简介
SM3适用于商用密码应用中的数字签名和验证，是在SHA-256基础上改进实现的一种算法，其安全性和SHA-256相当。SM3和MD5的迭代过程类似，也采用Merkle-Damgard结构。消息分组长度为512位，摘要值长度为256位  
SM3具有抗碰撞性和抗第二原像性，适合高吞吐场景，在数字签名、数据完整性校验、区块链以及物联网方面都有应用。
## SM3基本原理
整个算法的执行过程可以概括成四个步骤：消息填充、消息扩展、迭代压缩、输出结果  
- 消息填充  
SM3的消息扩展步骤是以512位的数据分组作为输入的。因此，我们需要在一开始就把数据长度填充至512位的倍数。数据填充规则和MD5一样，具体步骤如下：  
1、先填充一个“1”，后面加上k个“0”。其中k是满足(n+1+k) mod 512 = 448的最小正整数。  
2、追加64位的数据长度。  
- 消息扩展  
SM3的迭代压缩步骤没有直接使用数据分组进行运算，而是使用这个步骤产生的132个消息字。概括来说，先将一个512位数据分组划分为16个消息字，并且作为生成的132个消息字的前16个。再用这16个消息字递推生成剩余的116个消息字。  
在最终得到的132个消息字中，前68个消息字构成数列{W_j}，后64个消息字构成数列{W'_j}，其中下标j从0开始计数。
- 迭代压缩  
SM3为Merkle-Damgard结构，使用消息扩展得到的消息字进行运算，由压缩函数对每个512位分组执行64轮非线性操作（包括位运算、模加等）。
- 输出结果  
将经过一系列压缩函数得到的八个向量拼接，生成256位的哈希值。
## SM3代码实现
### 一、辅助函数
定义一些辅助函数：循环左移函数、布尔函数和置换函数
- 循环左移函数  
```C++
inline uint32_t ROL(uint32_t x, uint32_t n) {
    n %= 32;
    if (n == 0) return x;
    return (x << n) | (x >> (32 - n));
}
```
- 布尔函数  
FF0和GG0是相同的布尔函数，实现异或操作，FF1实现(X & Y) | (X & Z) | (Y & Z)，GG1实现(X & Y) | (~X & Z)。  
```C++
inline uint32_t FF0(uint32_t X, uint32_t Y, uint32_t Z) { return X ^ Y ^ Z; }
inline uint32_t FF1(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Y) | (X & Z) | (Y & Z); }
inline uint32_t GG0(uint32_t X, uint32_t Y, uint32_t Z) { return X ^ Y ^ Z; }
inline uint32_t GG1(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Y) | (~X & Z); }
```
- 置换函数  
置换函数通过对输入进行异或和循环移位操作来实现数据的混淆
```C++
inline uint32_t P0(uint32_t X) { return X ^ ROL(X, 9) ^ ROL(X, 17); }
inline uint32_t P1(uint32_t X) { return X ^ ROL(X, 15) ^ ROL(X, 23); }
```
### 二、SM3类
SM3类中包括重置、更新、最终化以及摘要等。  
- 重置  
初始化哈希状态为SM3的初始值
```C++
void reset() {
    state[0] = 0x7380166F;
    state[1] = 0x4914B2B9;
    state[2] = 0x172442D7;
    state[3] = 0xDA8A0600;
    state[4] = 0xA96F30BC;
    state[5] = 0x163138AA;
    state[6] = 0xE38DEE4D;
    state[7] = 0xB0FB0E4E;
    total_len = 0;
    buffer.clear();
}
```
- 更新  
分块处理数据
```C++
void update(const uint8_t* data, size_t len) {
    total_len += len;
    buffer.insert(buffer.end(), data, data + len);
    
    //处理完整的分块
    while (buffer.size() >= 64) {
        process_block(buffer.data());
        buffer.erase(buffer.begin(), buffer.begin() + 64);
    }
}
```
- 最终化  
按照填充规则来处理数据
```C++
    void finalize() {
        //计算消息长度
        uint64_t bit_len = total_len * 8;
        //进行填充
        buffer.push_back(0x80);

        size_t padding_len = 56 - (buffer.size() % 64);
        if (padding_len > 64) padding_len -= 64;  // 处理负值
        buffer.insert(buffer.end(), padding_len, 0);

        for (int i = 7; i >= 0; --i) {
            buffer.push_back((bit_len >> (i * 8)) & 0xFF);
        }

        //处理填充后的块
        for (size_t i = 0; i < buffer.size(); i += 64) {
            process_block(buffer.data() + i);
        }
        buffer.clear();
    }
```
- 摘要  
将哈希状态转换为十六进制字符串表示
```C++
  string digest() {
      stringstream ss;
      for (int i = 0; i < 8; ++i) {
          ss << hex << setfill('0') << setw(8) << state[i];
      }
      return ss.str();
  }
```
- 处理  
在process_block中，首先进行了消息扩展，生成W和W1数组，然后初始化寄存器A到H，执行64轮压缩函数，更新寄存器状态，最后将寄存器状态与哈希状态进行异或操作。
```C++
 void process_block(const uint8_t* block) {
     // 消息扩展
     uint32_t W[68];
     uint32_t W1[64];

     // 初始化前16个字
     for (int i = 0; i < 16; ++i) {
         W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
             (block[i * 4 + 2] << 8) | block[i * 4 + 3];
     }

     // 扩展其余部分
     for (int j = 16; j < 68; ++j) {
         W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL(W[j - 3], 15)) ^
             ROL(W[j - 13], 7) ^ W[j - 6];
     }

     // 计算W'
     for (int j = 0; j < 64; ++j) {
         W1[j] = W[j] ^ W[j + 4];
     }

     // 初始化寄存器
     uint32_t A = state[0];
     uint32_t B = state[1];
     uint32_t C = state[2];
     uint32_t D = state[3];
     uint32_t E = state[4];
     uint32_t F = state[5];
     uint32_t G = state[6];
     uint32_t H = state[7];

     // 压缩函数
     for (int j = 0; j < 64; ++j) {

         uint32_t Tj = (j < 16) ? 0x79CC4519 : 0x7A879D8A;
         uint32_t T_rot = ROL(Tj, j);

         uint32_t SS1 = ROL(ROL(A, 12) + E + T_rot, 7);
         uint32_t SS2 = SS1 ^ ROL(A, 12);
         uint32_t TT1 = (j < 16) ?
             (FF0(A, B, C) + D + SS2 + W1[j]) :
             (FF1(A, B, C) + D + SS2 + W1[j]);
         uint32_t TT2 = (j < 16) ?
             (GG0(E, F, G) + H + SS1 + W[j]) :
             (GG1(E, F, G) + H + SS1 + W[j]);

         D = C;
         C = ROL(B, 9);
         B = A;
         A = TT1;
         H = G;
         G = ROL(F, 19);
         F = E;
         E = P0(TT2);
     }

     state[0] ^= A;
     state[1] ^= B;
     state[2] ^= C;
     state[3] ^= D;
     state[4] ^= E;
     state[5] ^= F;
     state[6] ^= G;
     state[7] ^= H;
 }
```
## SM3的优化
对基本SM3算法的优化可以从查表优化、循环拆分、内存优化等方面进行
- 查表优化  
预计算64轮常量表 T_ROT，避免循环中重复计算 ROL(Tj, j)，使用静态常量表减少计算开销
```C++

```

- 循环拆分  
将64轮压缩循环拆分为前16轮和后48轮，消除循环内的条件判断，减少分支预测失败
```C++

```
- 寄存器重用  
使用局部变量保存中间结果，减少重复计算
```C++

```
- 内存优化  
使用缓冲区预分配（reserve(64)），改进update()的分块处理逻辑，减少内存复制
