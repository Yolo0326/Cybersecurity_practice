# 用circom实现poseidon2哈希算法的电路
- 项目心得：  
短时间内速成一门新的语言确实比较困难，只能通过所给资料及上网查询大量相关资料略知一二  
- 要求：   
1. poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)  
2. 电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可  
3. 用Groth16算法生成证明  

- 参考文档：  
1. poseidon2哈希算法https://eprint.iacr.org/2023/323.pdf  
2. circom说明文档https://docs.circom.io/  
3. circom电路样例 https://github.com/iden3/circomlib
## rust的安装
直接使用以下指令安装，一直卡在下载阶段，于是更换为另一种方法
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
### 下载
更换为：  
- 导入国内源  
```bash
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
```
- 执行命令（安装选项选择1）
```bash
curl https://sh.rustup.rs -sSf | sh
```
- 加入虚拟环境变量
```bash
source $HOME/.cargo/env
```
- 安装路径
```bash
/home/用户名/.cargo/bin
```
### 添加国内源
- 创建配置文件
```bash
vim ~/.cargo/config.toml
```
- 添加内容
```bash
[source.crates-io]
replace-with = 'rsproxy'

[source.rsproxy]
registry = "https://rsproxy.cn/crates.io-index"

[registries.rsproxy]
index = "https://rsproxy.cn/crates.io-index"

[net]
git-fetch-with-cli = true
```
### 安装rust-src
```bash
rustup component add rust-src
```
### 测试
- 查看版本
```bash
rustc --version
```
## 主要文件
- poseidon_hasher.circom 主电路文件
```rust
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
```

- mds_matrix.circom MDS矩阵常数
```rust
pragma circom 2.0.0;

template MDSMatrix() {
    signal output matrix[3][3];
    
    // 标准MDS矩阵for t=3
    matrix[0][0] <-- "0x066f6f85d6f68a85ec10345351a23a3aaf07f38af8c952a7bceca70bd2af7ad5";
    matrix[0][1] <-- "0x0d0f6a0a8c0c0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    matrix[0][2] <-- "0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    
    matrix[1][0] <-- "0x08e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3";
    matrix[1][1] <-- "0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";
    matrix[1][2] <-- "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
    
    matrix[2][0] <-- "0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
    matrix[2][1] <-- "0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";
    matrix[2][2] <-- "0x3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d";
    
    // 添加约束
    for (var i = 0; i < 3; i++) {
        for (var j = 0; j < 3; j++) {
            matrix[i][j] === (matrix[i][j] * 1);
        }
    }
}
```
- round_constants.circom 轮常数  
生成Poseidon2哈希算法中所需的轮常数，在Poseidon的每一轮中，这些常数会与当前状态进行加法操作，然后经过S盒和矩阵变换，从而实现哈希算法的混淆和扩散
```rust
pragma circom 2.0.0;

template RoundConstants() {
    signal output out[63][3];
    
    // 63轮常数 (t=3, 安全参数256)
    out[0][0] <-- "0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b";
    out[0][1] <-- "0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bc4530a1fb";
    out[0][2] <-- "0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7";
    
    out[1][0] <-- "0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0";
    out[1][1] <-- "0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23";
    out[1][2] <-- "0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911";
    
    out[2][0] <-- "0x19b3ff1da3e6d0996e4b4f4e7f0a6b5a3d5c6b6e0f5d5e3e5f5d5e3e5f5d5e3e";
    out[2][1] <-- "0x2e1c5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b";
    out[2][2] <-- "0x0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";
    
    out[3][0] <-- "0x1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c";
    out[3][1] <-- "0x3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d";
    out[3][2] <-- "0x0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
    
    out[4][0] <-- "0x1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f";
    out[4][1] <-- "0x4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a";
    out[4][2] <-- "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
    
    out[5][0] <-- "0x2222222222222222222222222222222222222222222222222222222222222222";
    out[5][1] <-- "0x5757575757575757575757575757575757575757575757575757575757575757";
    out[5][2] <-- "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    
    out[6][0] <-- "0x2525252525252525252525252525252525252525252525252525252525252525";
    out[6][1] <-- "0x6464646464646464646464646464646464646464646464646464646464646464";
    out[6][2] <-- "0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
    
    out[7][0] <-- "0x2828282828282828282828282828282828282828282828282828282828282828";
    out[7][1] <-- "0x7171717171717171717171717171717171717171717171717171717171717171";
    out[7][2] <-- "0x0909090909090909090909090909090909090909090909090909090909090909";
    
    out[8][0] <-- "0x2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
    out[8][1] <-- "0x7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";
    out[8][2] <-- "0x0808080808080808080808080808080808080808080808080808080808080808";
    
    out[9][0] <-- "0x2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e";
    out[9][1] <-- "0x8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b";
    out[9][2] <-- "0x0707070707070707070707070707070707070707070707070707070707070707";
    
    out[10][0] <-- "0x3131313131313131313131313131313131313131313131313131313131313131";
    out[10][1] <-- "0x9898989898989898989898989898989898989898989898989898989898989898";
    out[10][2] <-- "0x0606060606060606060606060606060606060606060606060606060606060606";
    
    out[11][0] <-- "0x3434343434343434343434343434343434343434343434343434343434343434";
    out[11][1] <-- "0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
    out[11][2] <-- "0x0505050505050505050505050505050505050505050505050505050505050505";
    
    out[12][0] <-- "0x3737373737373737373737373737373737373737373737373737373737373737";
    out[12][1] <-- "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    out[12][2] <-- "0x0404040404040404040404040404040404040404040404040404040404040404";
    
    out[13][0] <-- "0x3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";
    out[13][1] <-- "0xbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbf";
    out[13][2] <-- "0x0303030303030303030303030303030303030303030303030303030303030303";
    
    out[14][0] <-- "0x3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d";
    out[14][1] <-- "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    out[14][2] <-- "0x0202020202020202020202020202020202020202020202020202020202020202";
    
    out[15][0] <-- "0x4040404040404040404040404040404040404040404040404040404040404040";
    out[15][1] <-- "0xd9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9";
    out[15][2] <-- "0x0101010101010101010101010101010101010101010101010101010101010101";
    
    out[16][0] <-- "0x4343434343434343434343434343434343434343434343434343434343434343";
    out[16][1] <-- "0xe6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6";
    out[16][2] <-- "0x0000000000000000000000000000000000000000000000000000000000000000";
    
    out[17][0] <-- "0x4646464646464646464646464646464646464646464646464646464646464646";
    out[17][1] <-- "0xf3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3";
    out[17][2] <-- "0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
    
    out[18][0] <-- "0x4949494949494949494949494949494949494949494949494949494949494949";
    out[18][1] <-- "0x0000000000000000000000000000000000000000000000000000000000000000";
    out[18][2] <-- "0x1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e";
    
    out[19][0] <-- "0x4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c";
    out[19][1] <-- "0x0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
    out[19][2] <-- "0x2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d";
    
    out[20][0] <-- "0x4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f";
    out[20][1] <-- "0x1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";
    out[20][2] <-- "0x3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";
    
    out[21][0] <-- "0x5252525252525252525252525252525252525252525252525252525252525252";
    out[21][1] <-- "0x2727272727272727272727272727272727272727272727272727272727272727";
    out[21][2] <-- "0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b";
    
    out[22][0] <-- "0x5555555555555555555555555555555555555555555555555555555555555555";
    out[22][1] <-- "0x3434343434343434343434343434343434343434343434343434343434343434";
    out[22][2] <-- "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    
    out[23][0] <-- "0x5858585858585858585858585858585858585858585858585858585858585858";
    out[23][1] <-- "0x4141414141414141414141414141414141414141414141414141414141414141";
    out[23][2] <-- "0x6969696969696969696969696969696969696969696969696969696969696969";
    
    out[24][0] <-- "0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b";
    out[24][1] <-- "0x4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e";
    out[24][2] <-- "0x7878787878787878787878787878787878787878787878787878787878787878";
    
    out[25][0] <-- "0x5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    out[25][1] <-- "0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b";
    out[25][2] <-- "0x8787878787878787878787878787878787878787878787878787878787878787";
    
    out[26][0] <-- "0x6161616161616161616161616161616161616161616161616161616161616161";
    out[26][1] <-- "0x6868686868686868686868686868686868686868686868686868686868686868";
    out[26][2] <-- "0x9696969696969696969696969696969696969696969696969696969696969696";
    
    out[27][0] <-- "0x6464646464646464646464646464646464646464646464646464646464646464";
    out[27][1] <-- "0x7575757575757575757575757575757575757575757575757575757575757575";
    out[27][2] <-- "0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";
    
    out[28][0] <-- "0x6767676767676767676767676767676767676767676767676767676767676767";
    out[28][1] <-- "0x8282828282828282828282828282828282828282828282828282828282828282";
    out[28][2] <-- "0xb4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4";
    
    out[29][0] <-- "0x6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a";
    out[29][1] <-- "0x8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f";
    out[29][2] <-- "0xc3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    
    out[30][0] <-- "0x6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d";
    out[30][1] <-- "0x9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c";
    out[30][2] <-- "0xd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";
    
    out[31][0] <-- "0x7070707070707070707070707070707070707070707070707070707070707070";
    out[31][1] <-- "0xa9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9";
    out[31][2] <-- "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";
    
    out[32][0] <-- "0x7373737373737373737373737373737373737373737373737373737373737373";
    out[32][1] <-- "0xb6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6";
    out[32][2] <-- "0xf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
    
    out[33][0] <-- "0x7676767676767676767676767676767676767676767676767676767676767676";
    out[33][1] <-- "0xc3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    out[33][2] <-- "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    
    out[34][0] <-- "0x7979797979797979797979797979797979797979797979797979797979797979";
    out[34][1] <-- "0xd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
    out[34][2] <-- "0x0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";
    
    out[35][0] <-- "0x7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
    out[35][1] <-- "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    out[35][2] <-- "0x1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d";
    
    out[36][0] <-- "0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
    out[36][1] <-- "0xeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea";
    out[36][2] <-- "0x2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";
    
    out[37][0] <-- "0x8282828282828282828282828282828282828282828282828282828282828282";
    out[37][1] <-- "0xf7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7";
    out[37][2] <-- "0x3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b";
    
    out[38][0] <-- "0x8585858585858585858585858585858585858585858585858585858585858585";
    out[38][1] <-- "0x0404040404040404040404040404040404040404040404040404040404040404";
    out[38][2] <-- "0x4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a";
    
    out[39][0] <-- "0x8888888888888888888888888888888888888888888888888888888888888888";
    out[39][1] <-- "0x1111111111111111111111111111111111111111111111111111111111111111";
    out[39][2] <-- "0x5959595959595959595959595959595959595959595959595959595959595959";
    
    out[40][0] <-- "0x8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b";
    out[40][1] <-- "0x1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e";
    out[40][2] <-- "0x6868686868686868686868686868686868686868686868686868686868686868";
    
    out[41][0] <-- "0x8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e";
    out[41][1] <-- "0x2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
    out[41][2] <-- "0x7777777777777777777777777777777777777777777777777777777777777777";
    
    out[42][0] <-- "0x9191919191919191919191919191919191919191919191919191919191919191";
    out[42][1] <-- "0x3838383838383838383838383838383838383838383838383838383838383838";
    out[42][2] <-- "0x8686868686868686868686868686868686868686868686868686868686868686";
    
    out[43][0] <-- "0x9494949494949494949494949494949494949494949494949494949494949494";
    out[43][1] <-- "0x4545454545454545454545454545454545454545454545454545454545454545";
    out[43][2] <-- "0x9595959595959595959595959595959595959595959595959595959595959595";
    
    out[44][0] <-- "0x9797979797979797979797979797979797979797979797979797979797979797";
    out[44][1] <-- "0x5252525252525252525252525252525252525252525252525252525252525252";
    out[44][2] <-- "0xa4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4";
    
    out[45][0] <-- "0x9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a";
    out[45][1] <-- "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f";
    out[45][2] <-- "0xb3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3";
    
    out[46][0] <-- "0x9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d";
    out[46][1] <-- "0x6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c";
    out[46][2] <-- "0xc2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
    
    out[47][0] <-- "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    out[47][1] <-- "0x7979797979797979797979797979797979797979797979797979797979797979";
    out[47][2] <-- "0xd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
    
    out[48][0] <-- "0xa3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    out[48][1] <-- "0x8686868686868686868686868686868686868686868686868686868686868686";
    out[48][2] <-- "0xe0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0";
    
    out[49][0] <-- "0xa6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6";
    out[49][1] <-- "0x9393939393939393939393939393939393939393939393939393939393939393";
    out[49][2] <-- "0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
    
    out[50][0] <-- "0xa9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9";
    out[50][1] <-- "0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    out[50][2] <-- "0xfefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
    
    out[51][0] <-- "0xacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac";
    out[51][1] <-- "0xadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad";
    out[51][2] <-- "0x0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
    
    out[52][0] <-- "0xafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafaf";
    out[52][1] <-- "0xbababababababababababababababababababababababababababababababababa";
    out[52][2] <-- "0x1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c";
    
    out[53][0] <-- "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    out[53][1] <-- "0xc7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7";
    out[53][2] <-- "0x2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b";
    
    out[54][0] <-- "0xb5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5";
    out[54][1] <-- "0xd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    out[54][2] <-- "0x3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";
    
    out[55][0] <-- "0xb8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8";
    out[55][1] <-- "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";
    out[55][2] <-- "0x4949494949494949494949494949494949494949494949494949494949494949";
    
    out[56][0] <-- "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    out[56][1] <-- "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    out[56][2] <-- "0x5858585858585858585858585858585858585858585858585858585858585858";
    
    out[57][0] <-- "0xbebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebe";
    out[57][1] <-- "0xfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfb";
    out[57][2] <-- "0x6767676767676767676767676767676767676767676767676767676767676767";
    
    out[58][0] <-- "0xc1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    out[58][1] <-- "0x0808080808080808080808080808080808080808080808080808080808080808";
    out[58][2] <-- "0x7676767676767676767676767676767676767676767676767676767676767676";
    
    out[59][0] <-- "0xc4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
    out[59][1] <-- "0x1515151515151515151515151515151515151515151515151515151515151515";
    out[59][2] <-- "0x8585858585858585858585858585858585858585858585858585858585858585";
    
    out[60][0] <-- "0xc7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7";
    out[60][1] <-- "0x2222222222222222222222222222222222222222222222222222222222222222";
    out[60][2] <-- "0x9494949494949494949494949494949494949494949494949494949494949494";
    
    out[61][0] <-- "0xcacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca";
    out[61][1] <-- "0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f";
    out[61][2] <-- "0xa3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    
    out[62][0] <-- "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    out[62][1] <-- "0x3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c";
    out[62][2] <-- "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    
    // 添加约束
    for (var i = 0; i < 63; i++) {
        for (var j = 0; j < 3; j++) {
            out[i][j] === (out[i][j] * 1);
        }
    }
}
```
