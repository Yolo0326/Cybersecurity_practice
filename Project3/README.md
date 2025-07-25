# 用circom实现poseidon2哈希算法的电路
要求：   
1. poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)  
2. 电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可  
3. 用Groth16算法生成证明  

参考文档：  
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
