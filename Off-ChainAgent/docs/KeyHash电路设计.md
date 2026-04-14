# 密钥哈希电路约束指南

## 📌 概述

密钥哈希电路用来证明："**我知道一个密钥 k，使得 Poseidon2(k) = keyHash**"

这是 ZKCPlus 框架中 **Deliver 证明** 的核心约束，用于：
- 验证密钥的一致性
- 与加密/承诺一起组成完整的数据有效性证明

---

## 🔧 三层实现方案

### 1️⃣ **简化版：SimpleKeyHashCircuit**（最小复杂度）

```
目的：独立验证密钥哈希
约束数：~100-150个（取决于Poseidon2实现）
用法：仅验证"H(k) = h"
```

**电路定义**
```go
type SimpleKeyHashCircuit struct {
    Key     frontend.Variable  // 私有输入：密钥
    KeyHash frontend.Variable  // 公开输入：Poseidon2(Key)
}

Definition:
  1. poseidonHasher := NewHasher(api)
  2. computedHash := poseidonHasher.Hash(Key)
  3. Assert(computedHash == KeyHash)
```

**约束含义**
```
┌─────────────────────────────┐
│  Key (私有)                  │
│      ↓                       │
│  Poseidon2 映射              │
│      ↓                       │
│  = KeyHash (公开) ?          │ ← 公开验证
└─────────────────────────────┘

证明方说："我知道 Key，满足上述关系"
验证方只需看 KeyHash，无需知道 Key
```

---

### 2️⃣ **中间版：DeliverCircuit**（承诺链接）

```
目的：验证密钥哈希 + 数据承诺一致性
约束数：~200-300个
加入：Pedersen 承诺验证
```

**核心约束**
```
约束 1：Poseidon2(Key) = KeyHash
约束 2：Pedersen(Plaintext, Randomness) = CommitX
```

**数据流图**
```
证明方侧：
    Plaintext → [Pedersen承诺] → CommitX (公开)
    Key → [Poseidon2哈希] → KeyHash (公开)
    
验证方侧（只验证这两个公开约束）：
    ✓ KeyHash（由承诺的数据导出）
    ✓ CommitX（数据的公开锚点）
```

---

### 3️⃣ **完整版：DeliverExtendedCircuit**（端到端）

```
目的：完整的Deliver证明
约束数：~1000-1500个（含MiMC-CTR）
功能：密钥哈希 + 承诺 + 加密一致性
```

**三层约束分解**
```
┌──────────────────────────────────────┐
│ 约束层 1：密钥哈希验证                │
│   Poseidon2(Key) = KeyHash           │
├──────────────────────────────────────┤
│ 约束层 2：数据承诺验证                │
│   Pedersen(Plaintext, r) = CommitX   │
├──────────────────────────────────────┤
│ 约束层 3：加密正确性验证              │
│   ∀i: Ciphertext[i] =?               │
│        Selector[i] * (Plain[i] + KS) │
│   KS = MiMC(Nonce+i, Key)            │
└──────────────────────────────────────┘
```

---

## 🎯 关键实现细节

### 密钥哈希约束的数学形式

```
电路中：
  h_computed = Poseidon2(key)  [电路内部计算]
  Assert(h_computed == h_public)  [约束检查]

等价于证明：
  ∃ key ∈ Fp : Poseidon2(key) = h_public
```

### Poseidon2 在 gnark 中的集成

```go
// 为了在电路中使用 Poseidon2，需要：
import "github.com/consensys/gnark/std/algebra/native/poseidon2"

// 在 Define 方法中：
poseidonHasher, err := poseidon2.NewHasher(api)
if err != nil {
    return err
}
result := poseidonHasher.Hash(input)

// 生成的约束：
// - Poseidon2 轮函数展开
// - 约束数 ≈ sponge_state_size × rounds
// - 对 BN254：≈ 8 × 8 = 64 个乘法约束/Hash调用
```

---

## 📊 使用场景与对应电路

| 场景 | 选择电路 | 原因 |
|------|---------|------|
| 仅验证密钥 | `SimpleKeyHashCircuit` | 最小约束，最快验证 |
| Deliver证明+承诺 | `DeliverCircuit` | 跨证明链接 `c_x` |
| 完整ZKCPlus证明 | `DeliverExtendedCircuit` | 加密+承诺+哈希一体 |

---

## 🔄 集成流程

### 流程框图

```
[Step 1] 数据准备
    ├─ plaintext[]
    ├─ key
    └─ nonce

        ↓

[Step 2] 离线计算（电路外）
    ├─ keyHash = Poseidon2(key)        [这是公开参数]
    ├─ commitment = Pedersen(...)      [这是公开参数]
    └─ ciphertext[] = MiMC-CTR(...)    [这是公开参数]

        ↓

[Step 3] 编译电路到R1CS
    └─ Define() 生成约束

        ↓

[Step 4] Setup (Groth16/PlonK)
    └─ pk, vk

        ↓

[Step 5] 生成Witness
    ├─ 私有：key, plaintext[], randomness, nonce
    └─ 公开：keyHash, commitment, ciphertext[], selector[]

        ↓

[Step 6] Prove & Verify
    └─ 证明约束满足
```

---

## ⚠️ 重要注意事项

### 1. 公开输入 vs 私有输入

```go
type Circuit struct {
    // 公开输入（验证方知道）
    KeyHash frontend.Variable `gnark:",public"`
    
    // 私有输入（仅证明方知道）
    Key frontend.Variable  // 无标签 = 私有
}
```

**规则**：
- 标记 `` `gnark:",public"` `` 的字段是公开输入
- 验证时 keyHash 必须与证明中的公开部分匹配

### 2. 哈希值的类型转换

```go
// 问题：KeyPoseidonHash 返回 []byte，但电路需要 big.Int
keyHash := offchain.KeyPoseidonHash(key)      // []byte
keyHashInt := new(big.Int).SetBytes(keyHash)  // 转成 big.Int

// 在 Witness 中使用转换后的值
assignment.KeyHash = keyHashInt
```

### 3. 多哈希场景（多谓词）

```
若要验证多个谓词：
  φ₁: Poseidon2(x) = h₁
  φ₂: x ∈ [a,b]
  φ₃: ...
  
则需要：
  ✓ 每个谓词独立一个电路 + pk/vk
  ✓ 共享通用 SRS（PlonK）
  ✓ 后续可用 SnarkPack 聚合
```

---

## 🚀 下一步

### 修改 PLAN.md 进度

```markdown
#### 阶段二：引入 Pedersen 承诺
- [x] 在电路中生成哈希约束
- [ ] Deliver 证明电路实现 ← 已完成这一步
- [ ] 范围谓词 φ₁(x) ∈ [a,b]
- [ ] 选择性披露谓词 φ₂: x' = x ∘ b
- [ ] SnarkPack 聚合

#### 阶段三：迁移至 PlonK
- [ ] 替换 Groth16 → PlonK backend
- [ ] 调整 SRS 生成
```

### 测试命令

```bash
cd Off-ChainAgent/test
go run test_keyhash.go

# 或只运行简化电路
go test -run TestSimpleKeyHashCircuit -v
```

---

## 📖 参考资源

- **gnark Poseidon2**: https://github.com/Consensys/gnark-crypto/tree/master/ecc/bn254/fr/poseidon2
- **ZKCPlus 论文 §3.2**: Deliver 证明定义
- **Pedersen 承诺**: gnark/std/commitment/pedersen
