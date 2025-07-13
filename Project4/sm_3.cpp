#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include <sstream>

using namespace std;

// 循环左移
inline uint32_t ROL(uint32_t x, uint32_t n) {
    n %= 32;
    if (n == 0) return x;
    return (x << n) | (x >> (32 - n));
}

// 布尔函数
inline uint32_t FF0(uint32_t X, uint32_t Y, uint32_t Z) { return X ^ Y ^ Z; }
inline uint32_t FF1(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Y) | (X & Z) | (Y & Z); }
inline uint32_t GG0(uint32_t X, uint32_t Y, uint32_t Z) { return X ^ Y ^ Z; }
inline uint32_t GG1(uint32_t X, uint32_t Y, uint32_t Z) { return (X & Y) | (~X & Z); }

// 置换函数P0与P1
inline uint32_t P0(uint32_t X) { return X ^ ROL(X, 9) ^ ROL(X, 17); }
inline uint32_t P1(uint32_t X) { return X ^ ROL(X, 15) ^ ROL(X, 23); }

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
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        buffer.insert(buffer.end(), data, data + len);
        
        //处理完整的分块
        while (buffer.size() >= 64) {
            process_block(buffer.data());
            buffer.erase(buffer.begin(), buffer.begin() + 64);
        }
    }

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

    string digest() {
        stringstream ss;
        for (int i = 0; i < 8; ++i) {
            ss << hex << setfill('0') << setw(8) << state[i];
        }
        return ss.str();
    }

private:
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

int main() {
    // test
    cout << "SM3(\"abc\") = " << sm3_hash("abc") << endl;

    cout << "SM3(\"abcdabcdabcdabcdabcdabcdabcd\") = "<< sm3_hash("abcdabcdabcdabcdabcdabcdabcd") << endl;

    return 0;
}