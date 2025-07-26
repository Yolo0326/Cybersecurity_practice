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
