# 用circom实现poseidon2哈希算法的电路
要求：   
1. poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)  
2. 电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可  
3. 用Groth16算法生成证明  

参考文档：  
1. poseidon2哈希算法https://eprint.iacr.org/2023/323.pdf  
2. circom说明文档https://docs.circom.io/  
3. circom电路样例 https://github.com/iden3/circomlib

## PART1: Poseidon2Permutation
这一部分是实现Poseidon2置换的函数，其输入和输出都是3个元素的数组，参数设置包括素数p、全轮数RF、部分轮数RP和S-box指数d。  
线性层矩阵M_E和M_I用于线性变换，轮常数RC_full和RC_partial用于轮函数的常数添加。  
初始线性层对输入状态进行线性变换，此外还包括前4轮全轮，56轮部分轮和后4轮全轮。在前4轮全轮以及后4轮全轮中，每轮包括加轮常数、S-box和线性层，在56轮部分轮中，每轮只对第一个元素进行加轮常数、S-box和线性层。
