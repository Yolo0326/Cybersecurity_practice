#include <cstring>
#include <iostream>
#include <iomanip>
#include <immintrin.h>
#include <array>
#include <chrono>
using namespace std;

class SM4 {
private:
    // S盒
    static constexpr array<unsigned char, 256> S_BOX = {
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
    static constexpr array<unsigned int, 4> FK = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };

    // 固定参数CK
    static constexpr array<unsigned int, 32> CK = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    // 预计算的T表
    array<unsigned int, 256> T_table;
    array<unsigned int, 256> T_prime_table;

    // 轮密钥
    array<unsigned int, 32> roundKeys;

    // 循环左移
    static inline unsigned int leftRotate(unsigned int word, unsigned int bits) {
        return (word << bits) | (word >> (32 - bits));
    }

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

    // 非线性变换τ
    unsigned int tauTransform(unsigned int word) {
        unsigned int result = 0;
        for (int i = 0; i < 4; i++) {
            unsigned char byte = (word >> (24 - i * 8)) & 0xFF;
            result = (result << 8) | S_BOX[byte];
        }
        return result;
    }

    // T函数（加密）
    unsigned int tTransform(unsigned int word) {
        unsigned int b0 = S_BOX[(word >> 24) & 0xFF];
        unsigned int b1 = S_BOX[(word >> 16) & 0xFF];
        unsigned int b2 = S_BOX[(word >> 8) & 0xFF];
        unsigned int b3 = S_BOX[word & 0xFF];

        // 组合字节并应用线性变换
        unsigned int b = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        return b ^ leftRotate(b, 2)
            ^ leftRotate(b, 10)
            ^ leftRotate(b, 18)
            ^ leftRotate(b, 24);
    }

    // T'函数（密钥扩展）
    unsigned int tTransformPrime(unsigned int word) {
        unsigned int b0 = S_BOX[(word >> 24) & 0xFF];
        unsigned int b1 = S_BOX[(word >> 16) & 0xFF];
        unsigned int b2 = S_BOX[(word >> 8) & 0xFF];
        unsigned int b3 = S_BOX[word & 0xFF];

        // 组合字节并应用线性变换L'
        unsigned int b = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        return b ^ leftRotate(b, 13)
            ^ leftRotate(b, 23);
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
    // AVX2优化的T变换
    __m256i tTransformAVX2(__m256i word) const {

        __m256i b3 = _mm256_and_si256(word, _mm256_set1_epi32(0xFF));
        __m256i b2 = _mm256_and_si256(_mm256_srli_epi32(word, 8), _mm256_set1_epi32(0xFF));
        __m256i b1 = _mm256_and_si256(_mm256_srli_epi32(word, 16), _mm256_set1_epi32(0xFF));
        __m256i b0 = _mm256_srli_epi32(word, 24);

        // 使用预计算的T_table
        __m256i r0 = _mm256_i32gather_epi32(
            reinterpret_cast<const int*>(T_table.data()), b0, 4);
        __m256i r1 = _mm256_i32gather_epi32(
            reinterpret_cast<const int*>(T_table.data()), b1, 4);
        __m256i r2 = _mm256_i32gather_epi32(
            reinterpret_cast<const int*>(T_table.data()), b2, 4);
        __m256i r3 = _mm256_i32gather_epi32(
            reinterpret_cast<const int*>(T_table.data()), b3, 4);

        // 合并结果
        return _mm256_xor_si256(
            _mm256_xor_si256(r0, r1),
            _mm256_xor_si256(r2, r3));
    }
    // 转置函数，将8个分组转换为状态矩阵
    static void transpose_4x8_epi32(
        const __m256i& in0, const __m256i& in1, const __m256i& in2, const __m256i& in3,
        const __m256i& in4, const __m256i& in5, const __m256i& in6, const __m256i& in7,
        __m256i& out0, __m256i& out1, __m256i& out2, __m256i& out3
    ) {
        // 解包32位整数到128位通道
        __m256 a0 = _mm256_castsi256_ps(in0);
        __m256 a1 = _mm256_castsi256_ps(in1);
        __m256 a2 = _mm256_castsi256_ps(in2);
        __m256 a3 = _mm256_castsi256_ps(in3);
        __m256 a4 = _mm256_castsi256_ps(in4);
        __m256 a5 = _mm256_castsi256_ps(in5);
        __m256 a6 = _mm256_castsi256_ps(in6);
        __m256 a7 = _mm256_castsi256_ps(in7);

        // 转置4x4矩阵
        __m256 t0 = _mm256_unpacklo_ps(a0, a1);
        __m256 t1 = _mm256_unpackhi_ps(a0, a1);
        __m256 t2 = _mm256_unpacklo_ps(a2, a3);
        __m256 t3 = _mm256_unpackhi_ps(a2, a3);
        __m256 t4 = _mm256_unpacklo_ps(a4, a5);
        __m256 t5 = _mm256_unpackhi_ps(a4, a5);
        __m256 t6 = _mm256_unpacklo_ps(a6, a7);
        __m256 t7 = _mm256_unpackhi_ps(a6, a7);

        // 继续转置
        __m256 s0 = _mm256_shuffle_ps(t0, t2, 0x44);
        __m256 s1 = _mm256_shuffle_ps(t0, t2, 0xEE);
        __m256 s2 = _mm256_shuffle_ps(t1, t3, 0x44);
        __m256 s3 = _mm256_shuffle_ps(t1, t3, 0xEE);
        __m256 s4 = _mm256_shuffle_ps(t4, t6, 0x44);
        __m256 s5 = _mm256_shuffle_ps(t4, t6, 0xEE);
        __m256 s6 = _mm256_shuffle_ps(t5, t7, 0x44);
        __m256 s7 = _mm256_shuffle_ps(t5, t7, 0xEE);

        // 最终排列
        out0 = _mm256_castps_si256(_mm256_permute2f128_ps(s0, s4, 0x20));
        out1 = _mm256_castps_si256(_mm256_permute2f128_ps(s1, s5, 0x20));
        out2 = _mm256_castps_si256(_mm256_permute2f128_ps(s2, s6, 0x20));
        out3 = _mm256_castps_si256(_mm256_permute2f128_ps(s3, s7, 0x20));
    }
public:
    // 构造函数
    SM4(const unsigned char key[16]) {
        initLookupTables();
        keySchedule(key);
    }

    // 加密16字节数据块（循环展开优化）
    void encrypt(const unsigned char input[16], unsigned char output[16]) {
        // 将输入分成4个32位字（大端序）
        unsigned int x0, x1, x2, x3;
        x0 = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
        x1 = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | input[7];
        x2 = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | input[11];
        x3 = (input[12] << 24) | (input[13] << 16) | (input[14] << 8) | input[15];

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

        // 反序变换并输出
        unsigned int y0 = x3, y1 = x2, y2 = x1, y3 = x0;

        output[0] = (y0 >> 24) & 0xFF; output[1] = (y0 >> 16) & 0xFF;
        output[2] = (y0 >> 8) & 0xFF; output[3] = y0 & 0xFF;

        output[4] = (y1 >> 24) & 0xFF; output[5] = (y1 >> 16) & 0xFF;
        output[6] = (y1 >> 8) & 0xFF; output[7] = y1 & 0xFF;

        output[8] = (y2 >> 24) & 0xFF; output[9] = (y2 >> 16) & 0xFF;
        output[10] = (y2 >> 8) & 0xFF; output[11] = y2 & 0xFF;

        output[12] = (y3 >> 24) & 0xFF; output[13] = (y3 >> 16) & 0xFF;
        output[14] = (y3 >> 8) & 0xFF; output[15] = y3 & 0xFF;
    }

    // 解密16字节数据块
    void decrypt(const unsigned char input[16], unsigned char output[16]) {
        // 使用轮密钥的逆序
        array<unsigned int, 32> reverseKeys;
        for (int i = 0; i < 32; i++) {
            reverseKeys[i] = roundKeys[31 - i];
        }

        // 临时保存原始轮密钥
        auto tempKeys = roundKeys;

        // 使用逆序轮密钥
        roundKeys = reverseKeys;

        // 执行加密流程
        encrypt(input, output);

        // 恢复原始轮密钥
        roundKeys = tempKeys;
    }

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

};


// 测试
int main() {

    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    unsigned char plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    unsigned char ciphertext[16];
    unsigned char decrypted[16];

    SM4 sm4(key);

    cout << "原始明文: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0')
            << (int)plaintext[i] << " ";
    }
    cout << endl;

    // 加密
    sm4.encrypt(plaintext, ciphertext);
    cout << "加密结果: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0')
            << static_cast<int>(ciphertext[i]) << " ";
    }
    cout << std::endl;

    // 解密
    sm4.decrypt(ciphertext, decrypted);
    cout << "解密结果: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0')
            << static_cast<int>(decrypted[i]) << " ";
    }
    cout << endl;


    cout << "============== 性能测试 ==============" << endl;
    const size_t TEST_SIZE = 16 * 1024 * 1024;
    const size_t BLOCK_COUNT = TEST_SIZE / 16;
    unsigned char* bigData = new unsigned char[TEST_SIZE];
    unsigned char* encryptedData = new unsigned char[TEST_SIZE];
    unsigned char* decryptedData = new unsigned char[TEST_SIZE];

    // 初始化测试数据
    memset(bigData, 0xAA, TEST_SIZE);

    // 串行加密
    auto start = chrono::high_resolution_clock::now();
    for (size_t i = 0; i < BLOCK_COUNT; i++) {
        sm4.encrypt(bigData + i * 16, encryptedData + i * 16);
    }
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = end - start;
    cout << "串行加密 " << TEST_SIZE / (1024 * 1024) << "MB 数据耗时: "
        << fixed << setprecision(3) << elapsed.count() << " 秒" << endl;
    cout << "吞吐量: " << fixed << setprecision(2)
        << (TEST_SIZE / (1024.0 * 1024.0) / elapsed.count()) << " MB/s" << endl << endl;

    // 串行解密
    start = chrono::high_resolution_clock::now();
    for (size_t i = 0; i < BLOCK_COUNT; i++) {
        sm4.decrypt(encryptedData + i * 16, decryptedData + i * 16);
    }
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "串行解密 " << TEST_SIZE / (1024 * 1024) << "MB 数据耗时: "
        << fixed << setprecision(3) << elapsed.count() << " 秒" << endl;
    cout << "吞吐量: " << fixed << setprecision(2)
        << (TEST_SIZE / (1024.0 * 1024.0) / elapsed.count()) << " MB/s" << endl << endl;

    // 并行加密
    start = chrono::high_resolution_clock::now();
    sm4.encryptParallel(bigData, encryptedData, BLOCK_COUNT);
    end = chrono::high_resolution_clock::now();
    elapsed = end - start;
    cout << "并行加密 " << TEST_SIZE / (1024 * 1024) << "MB 数据耗时: "
        << fixed << setprecision(3) << elapsed.count() << " 秒" << endl;
    cout << "吞吐量: " << fixed << setprecision(2)
        << (TEST_SIZE / (1024.0 * 1024.0) / elapsed.count()) << " MB/s" << endl;
    cout << endl;

    if (memcmp(bigData, decryptedData, TEST_SIZE) == 0) {
        cout << "解密验证: 数据完全匹配" << endl;
    }
    else {
        cout << "解密验证: 数据不匹配" << endl;
    }

    delete[] bigData;
    delete[] encryptedData;
    delete[] decryptedData;

    return 0;
}