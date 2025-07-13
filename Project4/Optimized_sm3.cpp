#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include <sstream>
#include <ctime>

using namespace std;

// 循环左移
inline uint32_t ROL(uint32_t x, uint32_t n) {
    return (x << (n & 0x1F)) | (x >> ((32 - n) & 0x1F));
}

// 布尔函数
#define FF0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FF1(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GG1(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))

// 置换函数
#define P0(X) ((X) ^ ROL(X, 9) ^ ROL(X, 17))
#define P1(X) ((X) ^ ROL(X, 15) ^ ROL(X, 23))

class SM3 {
public:
    SM3() { reset(); }

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
        buffer.reserve(64);  
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        size_t offset = 0;

        // 处理缓冲区中已有的数据
        if (!buffer.empty()) {
            size_t fill = min(64 - buffer.size(), len);
            buffer.insert(buffer.end(), data, data + fill);
            offset += fill;

            if (buffer.size() == 64) {
                process_block(buffer.data());
                buffer.clear();
            }
        }

        // 处理完整块
        while (offset + 64 <= len) {
            process_block(data + offset);
            offset += 64;
        }

        // 保存剩余数据
        if (offset < len) {
            buffer.insert(buffer.end(), data + offset, data + len);
        }
    }

    void finalize() {
        uint64_t bit_len = total_len * 8;

        // 添加填充
        buffer.push_back(0x80);
        size_t len_mod = buffer.size() % 64;
        size_t padding_len = (len_mod <= 56) ? (56 - len_mod) : (120 - len_mod);
        buffer.insert(buffer.end(), padding_len, 0);

        // 添加长度
        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));
        }

        // 处理填充块
        for (size_t i = 0; i < buffer.size(); i += 64) {
            process_block(buffer.data() + i);
        }
        buffer.clear();
    }

    string digest() {
        stringstream ss;
        ss << hex << setfill('0');
        for (int i = 0; i < 8; ++i) {
            ss << setw(8) << state[i];
        }
        return ss.str();
    }

private:
    void process_block(const uint8_t* block) {
        // 消息扩展
        uint32_t W[68];
        uint32_t W1[64];

        // 加载前16个字
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
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

        // 寄存器变量
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        // 循环展开 
        for (int j = 0; j < 64; ++j) {
            uint32_t Tj = (j < 16) ? 0x79CC4519 : 0x7A879D8A; // 通过此条件避免分支嵌套
            uint32_t T_rot = ROL(Tj, j); // 运行时计算
            uint32_t A_rot12 = ROL(A, 12);
            uint32_t SS1 = ROL(A_rot12 + E + T_rot, 7);
            uint32_t SS2 = SS1 ^ A_rot12; // 中间结果复用

            uint32_t TT1, TT2;
            if (j < 16) {
                TT1 = FF0(A, B, C) + D + SS2 + W1[j];
                TT2 = GG0(E, F, G) + H + SS1 + W[j];
            }
            else {
                TT1 = FF1(A, B, C) + D + SS2 + W1[j];
                TT2 = GG1(E, F, G) + H + SS1 + W[j];
            }

            // 更新寄存器
            D = C;
            C = ROL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    uint32_t state[8];
    uint64_t total_len;
    vector<uint8_t> buffer;
};

string sm3_hash(const string& input) {
    SM3 sm3;
    sm3.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    sm3.finalize();
    return sm3.digest();
}

// test
int main() {

    cout << "SM3(\"abc\") = " << sm3_hash("abc") << endl;
    cout << "SM3(\"abcdabcdabcdabcdabcdabcdabcd\") = "<< sm3_hash("abcdabcdabcdabcdabcdabcdabcd") << endl;

    string long_str(1024 * 1024, 'a');
    clock_t start = clock();
    string hash = sm3_hash(long_str);
    clock_t end = clock();
    cout << "Time for 1MB data: "
        << (double)(end - start) / CLOCKS_PER_SEC * 1000
        << " ms" << endl;

    return 0;
}