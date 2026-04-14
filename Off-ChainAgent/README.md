# Off-ChainAgent

## 项目概述

Off-ChainAgent是一个基于**零知识证明（Zero-Knowledge Proof, ZKP）**的链下代理系统，采用Gnark框架实现。该项目是**ZKCPlus**的复现实现，主要关注密码学协议中的买卖双方互动场景，通过零知识证明确保数据隐私和交易安全。

## 技术栈

- **编程语言**: Go 1.25.5
- **ZK框架**: [Gnark v0.13.0](https://github.com/consensys/gnark) - 用于构建和验证零知识证明
- **密码学库**: Gnark-Crypto v0.18.0
- **椭圆曲线**: BN254（一个常用的配对友好曲线）
- **哈希算法**: 
  - MiMC（零知识友好的散列函数）
  - Poseidon2（新一代高效零知识散列函数）

## 项目结构

```
Off-ChainAgent/
├── src/                          # 核心源代码
│   ├── buyer.go                 # 买家端逻辑实现
│   ├── seller.go                # 卖家端逻辑实现
│   ├── ctr_mimc_gnark.go        # CTR-MiMC密码电路实现
│   ├── poseidon2hash.go         # Poseidon2哈希函数封装
│   └── shared.go                # 共享常量和配置
├── test/                         # 测试代码
│   ├── demo.go                  # 演示程序
│   └── test_seller.go           # 卖家端测试
├── data/                         # 数据文件
│   ├── data.txt                 # 原始数据
│   ├── encrypted_data.txt       # 加密数据
│   ├── publicInputs.json        # 公开证明输入
│   └── witness.json             # 证明见证数据
├── go.mod                        # Go模块定义文件
└── README.md                     # 项目文档（本文件）
```

## 核心功能模块

### 1. CTR模式MiMC密码 (`ctr_mimc_gnark.go`)
实现了基于**Counter (CTR) 模式**的**MiMC密码**电路：
- **轮函数**: 使用7次方运算 (x^7) 作为非线性变换
- **轮数**: 91轮密钥调度
- **最大文本长度**: 1024字符
- **电路约束**:
  - Selector数组验证（单调性：1...1,0...0）
  - 密钥流生成与加密
  - Padding区域约束

### 2. 买家端 (`buyer.go`)
- 加载公开输入（公开证明数据）
- 构造公开见证（public witness）
- 管理加密过程的公开部分
- 与证明系统交互

### 3. 卖家端 (`seller.go`)
- 读取明文数据
- 生成轮常量
- 密钥哈希生成（Key Hash）
- 提供完整的隐私数据用于证明生成

### 4. Poseidon2哈希 (`poseidon2hash.go`)
支持多条曲线上的Poseidon2哈希函数：
- BN254, BLS12-377, BLS12-381, BLS24-315, BLS24-317, BW6-633, BW6-761
- 适用于零知识证明的高效哈希运算

## 主要配置（`shared.go`）

```go
const (
    ROUNDS = 91      // MiMC轮数
    MAX_N  = 1024    // 最大文本长度限制
)
```

## 数据流与核心流程

1. **Seller (卖家)**: 
   - 拥有明文数据和密钥
   - 生成加密密文和轮常量
   - 计算密钥哈希

2. **加密过程**:
   - 使用MiMC-CTR模式加密明文
   - 生成密钥流：KS_i = MiMC(Nonce + i, Key)
   - 密文：C_i = P_i ⊕ KS_i

3. **零知识证明生成**:
   - 公开输入：密文、明文长度
   - 隐私见证：明文、密钥、Nonce
   - 证明约束验证正确的加密关系

4. **Buyer (买家)**:
   - 接收密文和公开证明
   - 验证零知识证明
   - 获得数据合法性保证

## 依赖关系

```
github.com/consensys/gnark v0.13.0
├── 核心ZK证明系统
├── Groth16证明算法
├── R1CS约束系统
└── Frontend电路编译器

github.com/consensys/gnark-crypto v0.18.0
├── 椭圆曲线运算 (BN254)
├── 标量域运算 (Fr)
├── 密码学原语
└── 哈希函数 (Poseidon2, MiMC)
```

## 构建与运行

### 前置要求
- Go 1.25.5 或更高版本
- 支持GOPATH或Go Module

### 依赖安装
```bash
go mod download
go mod tidy
```

### 编译
```bash
# 构建所有源文件
go build ./src

# 构建测试
go build ./test
```

### 运行测试/演示
```bash
# 运行演示程序
go run test/demo.go

# 运行卖家端测试
go run test/test_seller.go
```

## 密钥参数说明

### 公开参数 (Public Inputs - `publicInputs.json`)
- **Ciphertext**: 密文数组
- **TextLen**: 明文实际长度

### 隐私见证 (Witness - `witness.json`)
- **Plaintext**: 明文数据数组
- **Key**: 加密密钥
- **Nonce**: 密钥流初始化向量
- **Selector**: 选择器数组（标记有效位置）

## 代码示例

### MiMC轮函数（电路版本）
```go
// 计算 x^7
func Pow7(api frontend.API, x frontend.Variable) frontend.Variable {
    x2 := api.Mul(x, x)   // x^2
    x3 := api.Mul(x2, x)  // x^3
    x6 := api.Mul(x3, x3) // x^6
    x7 := api.Mul(x6, x)  // x^7
    return x7
}
```

### CTR-MiMC电路定义
```go
type CTRMiMCCircuit struct {
    Plaintext  [MAX_N]frontend.Variable  // 明文
    Ciphertext [MAX_N]frontend.Variable  // 密文
    TextLen    frontend.Variable         // 文本长度
    Selector   [MAX_N]frontend.Variable  // 选择器
    Key        frontend.Variable         // 密钥
    Nonce      frontend.Variable         // Nonce
}
```

## 应用场景

1. **隐私保护的电子商务**: 买卖双方可在不透露交易内容的前提下证明交易的合法性
2. **数据所有权证明**: 证明拥有特定加密数据的明文而无需披露数据本身
3. **密钥管理**: 安全的密钥交换与验证
4. **审计与合规**: 提供可验证的审计日志而保护隐私

## 椭圆曲线说明

**BN254** 是一条254位的Barreto-Naehrig曲线，具有以下特点：
- 支持配对运算 (Pairing-friendly)
- 适合Groth16证明系统
- 标量域阶数：r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
- 广泛用于零知识证明系统

## 常见问题

### Q: 什么是MiMC?
A: MiMC是一种为零知识证明优化的对称密钥密码。相比AES，MiMC在ZK电路中的约束数更少，计算成本更低。

### Q: 为什么使用Poseidon2而不是SHA256?
A: Poseidon2是专门为零知识应用设计的哈希函数，在算术约束中的成本远低于SHA256。

### Q: CTR模式是什么?
A: CTR (Counter Mode) 是一种流密码模式，通过加密递增的计数器生成密钥流，然后与明文进行异或运算。

## 许可证

该项目为毕业设计项目，基于ZKCPlus复现实现。

## 贡献与联系

如有问题或建议，欢迎通过Issue或Pull Request联系。

---

**最后更新**: 2026年3月
**项目路径**: `Off-ChainAgent`
