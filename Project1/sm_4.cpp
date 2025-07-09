#include <cstring>
#include <iostream>
#include <iomanip>
#include <chrono>
using namespace std;

class SM4 {
private:
    // S盒
    static const unsigned char S_BOX[256];
    // 系统参数FK
    static const unsigned int FK[4];
    // 固定参数CK
    static const unsigned int CK[32];

    // 32个轮密钥
    unsigned int roundKeys[32];

    // 循环左移
    static inline unsigned int leftRotate(unsigned int word, unsigned int bits) {
        return (word << bits) | (word >> (32 - bits));
    }

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

public:
    // 构造函数
    SM4(const unsigned char key[16]) {
        keySchedule(key);
    }

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
};

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

    // 加密测试
    sm4.encrypt(plaintext, ciphertext);
    cout << "加密结果: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0')
            << (int)ciphertext[i] << " ";
    }
    cout << endl;

    // 解密测试
    sm4.decrypt(ciphertext, decrypted);
    cout << "解密结果: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << setw(2) << setfill('0')
            << (int)decrypted[i] << " ";
    }
    cout << endl;

    return 0;
}