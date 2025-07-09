# SM4算法的软件实现及优化
## SM4算法简介
SM4算法是一个对称分组密码算法，分组长度与密钥长度均为128比特，其加密算法和密钥扩展算法都采用了32轮非线性迭代结构，解密算法和加密算法的结构相同，除了轮密钥的使用顺序是加密轮密钥的逆序。  
SM4算法的安全强度达到2^128，可抗差分攻击，合规性强，设计简单，符合中国国密标准。  
## SM4算法工作流程
### 一、SM4加解密
1.密钥扩展：将初始密钥通过非线性变换生成32个轮密钥。  
2.迭代加密：明文分组经过32轮非线性变换，每轮使用一个轮密钥。  
3.密文输出：最终迭代结果经逆初始变换生成密文。  
### 二、密钥扩展
密钥扩展过程与加解密类似，同样要经过拆分、过S盒、行移位列混合、密钥混合等操作，执行32轮获得32个轮密钥。  
#### 轮函数结构
1.S盒替换：8位输入通过复合域S盒进行非线性替换，增强抗差分攻击能力。  
2.线性变换：包括行移位、列混合等操作，扩散数据变化。  
3.密钥混合：轮密钥与中间状态进行异或运算。  

## 具体实现流程
### 一、定义基本参数
定义S盒、FK0~FK3、CK数组
```C++
// S盒
const unsigned char SM4::S_BOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// 系统参数FK
const unsigned int SM4::FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// 固定参数CK
const unsigned int SM4::CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
```
### 二、定义基本函数
基本变换包括非线性变换τ以及线性变换L和L'，并基于基本变换实现T函数和T'函数，最后实现密钥扩展，生成轮密钥
```C++
    // 非线性变换τ（S盒替换）
    static unsigned int tauTransform(unsigned int word) {
        unsigned int result = 0;
        for (int i = 0; i < 4; i++) {
            // 提取每个字节
            unsigned char byte = (word >> (24 - i * 8)) & 0xFF;
            // S盒替换
            byte = S_BOX[byte];
            // 重新组合
            result = (result << 8) | byte;
        }
        return result;
    }

    // 线性变换L（轮函数）
    static unsigned int linearTransform(unsigned int word) {
        return word ^ leftRotate(word, 2) ^ leftRotate(word, 10)
            ^ leftRotate(word, 18) ^ leftRotate(word, 24);
    }

    // 线性变换L'（密钥扩展）
    static unsigned int linearTransformPrime(unsigned int word) {
        return word ^ leftRotate(word, 13) ^ leftRotate(word, 23);
    }

    // T函数（轮函数）
    static unsigned int tTransform(unsigned int word) {
        return linearTransform(tauTransform(word));
    }

    // T'函数（密钥扩展）
    static unsigned int tTransformPrime(unsigned int word) {
        return linearTransformPrime(tauTransform(word));
    }

    // 密钥扩展
    void keySchedule(const unsigned char key[16]) {
        // 将16字节密钥转换为4个32位字（大端序）
        unsigned int k[4];
        for (int i = 0; i < 4; i++) {
            k[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16)
                | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        // 初始化轮密钥
        unsigned int kx[36];
        kx[0] = k[0] ^ FK[0];
        kx[1] = k[1] ^ FK[1];
        kx[2] = k[2] ^ FK[2];
        kx[3] = k[3] ^ FK[3];

        // 生成32个轮密钥
        for (int i = 0; i < 32; i++) {
            kx[i + 4] = kx[i] ^ tTransformPrime(kx[i + 1] ^ kx[i + 2] ^ kx[i + 3] ^ CK[i]);
            roundKeys[i] = kx[i + 4];
        }
    }

```
### 三、加解密实现
加密过程：先对输入进行分组，将输入分为4组32bits的数据，接着进行轮密钥异或、过S盒、行移位列混合等操作，迭代32轮，最后将生成的最后4个32bits数据反序合并，作为最后的输出结果  
解密过程：解密过程与加密过程类似，将加密得到的结果作为输入，逆序使用轮密钥，经过和加密同样的流程，反序合并最后4个32bits数据便得到对应的明文  
```C++
// 加密
void encrypt(const unsigned char input[16], unsigned char output[16]) {
    // 将输入分成4个32位字（大端序）
    unsigned int x[4];
    for (int i = 0; i < 4; i++) {
        x[i] = (input[i * 4] << 24) | (input[i * 4 + 1] << 16)
            | (input[i * 4 + 2] << 8) | input[i * 4 + 3];
    }

    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        unsigned int temp = x[0] ^ tTransform(x[1] ^ x[2] ^ x[3] ^ roundKeys[i]);
        // 更新状态
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }

    // 反序变换并输出
    unsigned int y[4] = { x[3], x[2], x[1], x[0] };
    for (int i = 0; i < 4; i++) {
        output[i * 4] = (y[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (y[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (y[i] >> 8) & 0xFF;
        output[i * 4 + 3] = y[i] & 0xFF;
    }
}

// 解密
void decrypt(const unsigned char input[16], unsigned char output[16]) {
    // 使用轮密钥的逆序
    unsigned int reverseKeys[32];
    for (int i = 0; i < 32; i++) {
        reverseKeys[i] = roundKeys[31 - i];
    }

    // 临时保存原始轮密钥
    unsigned int tempKeys[32];
    memcpy(tempKeys, roundKeys, sizeof(roundKeys));

    // 使用逆序轮密钥
    memcpy(roundKeys, reverseKeys, sizeof(reverseKeys));

    // 解密
    encrypt(input, output);

    // 恢复原始轮密钥
    memcpy(roundKeys, tempKeys, sizeof(roundKeys));
}
```

## 优化方法
- 启用增强指令集：高级向量扩展2 (/arch:AVX2)  
- 基本运行时检查：默认值  
- 安全检查：禁用安全检查 (/GS-)  
### 一、查表优化
预计算T函数和T'函数的结果，在轮函数中通过查表替代位运算。
```C++
// 初始化预计算表
void initLookupTables() {
    // 预计算T函数表
    for (int i = 0; i < 256; i++) {
        unsigned int b = S_BOX[i];
        // 线性变换L
        unsigned int r = b;
        r ^= leftRotate(b, 2);
        r ^= leftRotate(b, 10);
        r ^= leftRotate(b, 18);
        r ^= leftRotate(b, 24);
        T_table[i] = r;

        // 线性变换L'（密钥扩展）
        unsigned int r_prime = b;
        r_prime ^= leftRotate(b, 13);
        r_prime ^= leftRotate(b, 23);
        T_prime_table[i] = r_prime;
    }
}
```
### 二、循环展开
将32轮迭代展开为每次处理4轮，减少开销。
```C++
 // 32轮迭代
 for (int i = 0; i < 32; i += 4) {
     // 第1轮
     unsigned int temp = x0 ^ tTransform(x1 ^ x2 ^ x3 ^ roundKeys[i]);
     x0 = x1;
     x1 = x2;
     x2 = x3;
     x3 = temp;

     // 第2轮
     temp = x0 ^ tTransform(x1 ^ x2 ^ x3 ^ roundKeys[i + 1]);
     x0 = x1;
     x1 = x2;
     x2 = x3;
     x3 = temp;

     // 第3轮
     temp = x0 ^ tTransform(x1 ^ x2 ^ x3 ^ roundKeys[i + 2]);
     x0 = x1;
     x1 = x2;
     x2 = x3;
     x3 = temp;

     // 第4轮
     temp = x0 ^ tTransform(x1 ^ x2 ^ x3 ^ roundKeys[i + 3]);
     x0 = x1;
     x1 = x2;
     x2 = x3;
     x3 = temp;
 }
```
### 三、数据并行
使用SIMD指令进行并行处理，一次处理多个分组。
```C++
// AVX2并行加密
void encryptParallel(const unsigned char* input, unsigned char* output, size_t numBlocks) {
    // 确保输入输出内存对齐
    constexpr size_t alignment = 32;
    if (reinterpret_cast<uintptr_t>(input) % alignment != 0 ||
        reinterpret_cast<uintptr_t>(output) % alignment != 0) {
        // 回退到串行处理
        for (size_t i = 0; i < numBlocks; i++) {
            encrypt(input + i * 16, output + i * 16);
        }
        return;
    }

    // AVX2并行处理（每次处理8个分组）
    for (size_t i = 0; i < numBlocks; i += 8) {
        // 加载8个分组
        __m256i data0 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + i * 16));
        __m256i data1 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 1) * 16));
        __m256i data2 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 2) * 16));
        __m256i data3 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 3) * 16));
        __m256i data4 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 4) * 16));
        __m256i data5 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 5) * 16));
        __m256i data6 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 6) * 16));
        __m256i data7 = _mm256_load_si256(reinterpret_cast<const __m256i*>(input + (i + 7) * 16));

        // 重组数据：转置为状态矩阵
        // 每个__m256i包含8个分组中相同位置的状态字
        __m256i x0, x1, x2, x3;
        transpose_4x8_epi32(data0, data1, data2, data3, data4, data5, data6, data7, x0, x1, x2, x3);

        // 32轮迭代
        for (int round = 0; round < 32; round++) {
            __m256i rk = _mm256_set1_epi32(roundKeys[round]);

            // 计算: X0 ^ T(X1 ^ X2 ^ X3 ^ rk)
            __m256i temp = _mm256_xor_si256(x1, x2);
            temp = _mm256_xor_si256(temp, x3);
            temp = _mm256_xor_si256(temp, rk);
            temp = tTransformAVX2(temp);
            temp = _mm256_xor_si256(x0, temp);

            // 更新状态
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = temp;
        }

        // 反序变换
        __m256i y0 = x3, y1 = x2, y2 = x1, y3 = x0;

        // 转置回原始布局
        transpose_4x8_epi32(y0, y1, y2, y3, data0, data1, data2, data3, data4, data5, data6, data7);

        // 存储结果
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + i * 16), data0);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 1) * 16), data1);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 2) * 16), data2);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 3) * 16), data3);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 4) * 16), data4);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 5) * 16), data5);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 6) * 16), data6);
        _mm256_store_si256(reinterpret_cast<__m256i*>(output + (i + 7) * 16), data7);
    }

    // 处理剩余分组
    size_t processed = (numBlocks / 8) * 8;
    for (size_t i = processed; i < numBlocks; i++) {
        encrypt(input + i * 16, output + i * 16);
    }
}
```
## 运行结果
未优化：result1.png  
优化后：result2.png
