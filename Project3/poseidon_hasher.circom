pragma circom 2.0.0;

include "constants/round_constants.circom";
include "constants/mds_matrix.circom";

// S-box操作 (x^5)
template Sbox() {
    signal input in;
    signal output out;
    signal in2 <== in * in;    // in^2
    signal in4 <== in2 * in2;  // in^4
    out <== in4 * in;          // in^5
}

// 完整轮函数
template FullRound(round_idx) {
    signal input in[3];
    signal output out[3];
    
    component sbox[3];
    component round_const = RoundConstants();
    component mds = MDSMatrix();

    // 添加轮常数
    signal added_rc[3];
    for (var i = 0; i < 3; i++) {
        added_rc[i] <== in[i] + round_const.out[round_idx][i];
    }

    // S-box层
    for (var i = 0; i < 3; i++) {
        sbox[i] = Sbox();
        sbox[i].in <== added_rc[i];
    }

    // MDS矩阵乘法
    for (var i = 0; i < 3; i++) {
        out[i] <== mds.matrix[i][0] * sbox[0].out + 
                  mds.matrix[i][1] * sbox[1].out + 
                  mds.matrix[i][2] * sbox[2].out;
    }
}

// 部分轮函数
template PartialRound(round_idx) {
    signal input in[3];
    signal output out[3];
    
    component sbox = Sbox();
    component round_const = RoundConstants();
    component mds = MDSMatrix();

    // 添加轮常数
    signal added_rc[3];
    for (var i = 0; i < 3; i++) {
        added_rc[i] <== in[i] + round_const.out[round_idx][i];
    }

    // 仅第一个元素应用S-box
    sbox.in <== added_rc[0];
    signal sboxed[3] = [sbox.out, added_rc[1], added_rc[2]];

    // MDS矩阵乘法
    for (var i = 0; i < 3; i++) {
        out[i] <== mds.matrix[i][0] * sboxed[0] + 
                  mds.matrix[i][1] * sboxed[1] + 
                  mds.matrix[i][2] * sboxed[2];
    }
}

// Poseidon2主函数 (t=3, d=5)
template Poseidon2() {
    signal input in[2];        // 两个128位输入元素
    signal output out;         // 哈希输出
    
    // 初始化状态: [in0, in1, 0]
    signal state[3] = [in[0], in[1], 0];
    
    // 轮配置: 8轮完整 + 47轮部分 + 8轮完整 = 63轮
    component full_rounds1[8];
    component partial_rounds[47];
    component full_rounds2[8];
    
    // 第一组完整轮
    for (var r = 0; r < 8; r++) {
        full_rounds1[r] = FullRound(r);
        if (r == 0) {
            full_rounds1[r].in <== state;
        } else {
            full_rounds1[r].in <== full_rounds1[r-1].out;
        }
    }
    
    // 部分轮
    for (var r = 0; r < 47; r++) {
        partial_rounds[r] = PartialRound(8 + r);
        if (r == 0) {
            partial_rounds[r].in <== full_rounds1[7].out;
        } else {
            partial_rounds[r].in <== partial_rounds[r-1].out;
        }
    }
    
    // 第二组完整轮
    for (var r = 0; r < 8; r++) {
        full_rounds2[r] = FullRound(55 + r);
        if (r == 0) {
            full_rounds2[r].in <== partial_rounds[46].out;
        } else {
            full_rounds2[r].in <== full_rounds2[r-1].out;
        }
    }
    
    // 输出状态中的第一个元素
    out <== full_rounds2[7].out[0];
}

// 主电路
template Poseidon2Hasher() {
    // 公开输入: 哈希值
    signal input hash;
    
    // 隐私输入: 256位原始消息
    signal private input in_bits[256];
    
    // 将256位拆分为两个128位整数
    component bits2num0 = Bits2Num(128);
    component bits2num1 = Bits2Num(128);
    
    for (var i = 0; i < 128; i++) {
        bits2num0.in[i] <== in_bits[i];
        bits2num1.in[i] <== in_bits[i + 128];
    }
    
    // Poseidon2哈希计算
    component poseidon = Poseidon2();
    poseidon.in[0] <== bits2num0.out;
    poseidon.in[1] <== bits2num1.out;
    
    // 验证公开输入匹配计算结果
    poseidon.out === hash;
}

template Bits2Num(n) {
    signal input in[n];
    signal output out;
    var lc = 0;
    for (var i = 0; i < n; i++) {
        lc += in[i] * (1 << i);
    }
    out <== lc;
}

// 主组件
component main {public [hash]} = Poseidon2Hasher();
