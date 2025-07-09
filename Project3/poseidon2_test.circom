```rust
pragma circom 2.0.0;

// Poseidon2 置换核心组件
template Poseidon2Permutation() {
    signal input in[3];   // 输入状态
    signal output out[3]; // 输出状态

    // 参数设置 (示例值，实际使用时需要替换为正式参数)
    const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // BN254 素数
    const RF = 8;  // 全轮数
    const RP = 56; // 部分轮数
    const d = 5;   // S-box 指数
    
    // 线性层矩阵 (示例 MDS 矩阵)
    var M_E = [
        [5, 7, 1],
        [3, 4, 6],
        [1, 1, 1]
    ];
    var M_I = [
        [5, 1, 1],
        [1, 7, 1],
        [1, 1, 6]
    ];

    // 轮常数 (示例值)
    var RC_full = new Array(RF*3);
    var RC_partial = new Array(RP);
    for (var i = 0; i < RF*3; i++) RC_full[i] = i % p;
    for (var i = 0; i < RP; i++) RC_partial[i] = i % p;

    // === 初始线性层 ===
    signal state[3];
    state[0] <== M_E[0][0]*in[0] + M_E[0][1]*in[1] + M_E[0][2]*in[2];
    state[1] <== M_E[1][0]*in[0] + M_E[1][1]*in[1] + M_E[1][2]*in[2];
    state[2] <== M_E[2][0]*in[0] + M_E[2][1]*in[1] + M_E[2][2]*in[2];

    // === 前4轮全轮 ===
    for (var r = 0; r < RF/2; r++) {
        // 加轮常数
        for (var i = 0; i < 3; i++) {
            state[i] <== state[i] + RC_full[r*3 + i];
        }
        
        // S-box (x^5)
        for (var i = 0; i < 3; i++) {
            signal sq <== state[i] * state[i];
            signal quad <== sq * sq;
            state[i] <== quad * state[i];
        }
        
        // 线性层
        signal new_state[3];
        new_state[0] <== M_E[0][0]*state[0] + M_E[0][1]*state[1] + M_E[0][2]*state[2];
        new_state[1] <== M_E[1][0]*state[0] + M_E[1][1]*state[1] + M_E[1][2]*state[2];
        new_state[2] <== M_E[2][0]*state[0] + M_E[2][1]*state[1] + M_E[2][2]*state[2];
        state[0] <== new_state[0];
        state[1] <== new_state[1];
        state[2] <== new_state[2];
    }

    // === 56轮部分轮 ===
    for (var r = 0; r < RP; r++) {
        // 只对第一个元素加轮常数
        state[0] <== state[0] + RC_partial[r];
        
        // 只对第一个元素应用S-box
        signal sq <== state[0] * state[0];
        signal quad <== sq * sq;
        state[0] <== quad * state[0];
        
        // 线性层
        signal new_state[3];
        new_state[0] <== M_I[0][0]*state[0] + M_I[0][1]*state[1] + M_I[0][2]*state[2];
        new_state[1] <== M_I[1][0]*state[0] + M_I[1][1]*state[1] + M_I[1][2]*state[2];
        new_state[2] <== M_I[2][0]*state[0] + M_I[2][1]*state[1] + M_I[2][2]*state[2];
        state[0] <== new_state[0];
        state[1] <== new_state[1];
        state[2] <== new_state[2];
    }

    // === 后4轮全轮 ===
    for (var r = RF/2; r < RF; r++) {
        // 加轮常数
        for (var i = 0; i < 3; i++) {
            state[i] <== state[i] + RC_full[r*3 + i];
        }
        
        // S-box (x^5)
        for (var i = 0; i < 3; i++) {
            signal sq <== state[i] * state[i];
            signal quad <== sq * sq;
            state[i] <== quad * state[i];
        }
        
        // 线性层
        signal new_state[3];
        new_state[0] <== M_E[0][0]*state[0] + M_E[0][1]*state[1] + M_E[0][2]*state[2];
        new_state[1] <== M_E[1][0]*state[0] + M_E[1][1]*state[1] + M_E[1][2]*state[2];
        new_state[2] <== M_E[2][0]*state[0] + M_E[2][1]*state[1] + M_E[2][2]*state[2];
        state[0] <== new_state[0];
        state[1] <== new_state[1];
        state[2] <== new_state[2];
    }

    // 输出最终状态
    out[0] <== state[0];
    out[1] <== state[1];
    out[2] <== state[2];
}

// Poseidon2 哈希函数 (2-1 压缩模式)
template Poseidon2Hash() {
    signal input in0;     // 隐私输入1
    signal input in1;     // 隐私输入2
    signal output out;    // 公开输出 (哈希值)
    
    // 初始化状态: [in0, in1, 0]
    signal input_state[3];
    input_state[0] <== in0;
    input_state[1] <== in1;
    input_state[2] <== 0;
    
    // 应用Poseidon2置换
    component permutation = Poseidon2Permutation();
    for (var i = 0; i < 3; i++) {
        permutation.in[i] <== input_state[i];
    }
    
    // 压缩函数: output = permutation(input) + input
    signal output_state[3];
    output_state[0] <== permutation.out[0] + input_state[0];
    output_state[1] <== permutation.out[1] + input_state[1];
    output_state[2] <== permutation.out[2] + input_state[2];
    
    // 截取第一个元素作为哈希输出
    out <== output_state[0];
}

// 主组件 (Groth16 兼容)
component main = Poseidon2Hash();
```
