# Off-ChainAgent

Off-ChainAgent 是 `ZKCPlus` 复现项目中的链下代理模块，负责以下核心能力：

- 基于 MiMC-CTR 的链下数据加解密
- 基于 gnark 的零知识电路构建、证明与验证（Groth16 / Plonk）
- 密钥哈希（Poseidon2）与 Pedersen 承诺
- 可选的 Hyperledger Fabric 交易流程联调（CreateTrade -> LockTrade -> SubmitKeyandVerify）

## 技术栈

- Go `1.25.5`
- [gnark](https://github.com/Consensys/gnark) `v0.13.0`
- gnark-crypto `v0.18.0`
- Hyperledger Fabric Gateway Go SDK `v1.9.0`
- 椭圆曲线：BN254

## 目录结构

```text
Off-ChainAgent/
├─ src/
│  ├─ ctr_mimc_gnark.go      # MiMC-CTR 电路、Pedersen 承诺约束、ElGamal 电路
│  ├─ seller.go              # 卖方侧逻辑：读取明文、加密、导出证明相关文件
│  ├─ buyer.go               # 买方侧逻辑：读取公共输入、验证、解密
│  ├─ keyhash.go             # 密钥 Poseidon2 哈希导出
│  ├─ poseidon2hash.go       # 多曲线 Poseidon2 封装
│  ├─ predicate.go           # 扩展谓词电路（范围、选择性披露等）
│  ├─ fabric_client.go       # Fabric Gateway 客户端封装
│  ├─ srs.go                 # KZG SRS 导入导出
│  └─ shared.go              # 全局常量（ROUNDS/MAX_N）
├─ test/
│  ├─ test_tradeflow.go      # 主流程演示（本地证明 + 可选链上调用）
│  ├─ test_elgamal.go        # ElGamal 与点哈希相关测试函数
│  ├─ test_hash.go           # Key Hash 导出测试函数
│  └─ demo.go                # 小型演示代码
├─ data/                     # 示例输入输出与证明产物
├─ docs/                     # 补充文档
├─ go.mod
└─ README.md
```

## 快速开始

在 `Off-ChainAgent` 目录执行：

```bash
go mod tidy
go test ./...
```

说明：当前 `go test ./...` 主要用于编译检查（无 `_test.go` 单元测试）。

## 运行主流程

```bash
go run ./test
```

该命令会执行 `test/test_tradeflow.go`，包含：

1. 读取 `data/data.txt` 明文
2. MiMC-CTR 加密与解密一致性校验
3. 导出 `publicInputs.json / witness.json / proof.bin / vk.bin / pk.bin`
4. Groth16 证明与验证
5. Plonk 证明与验证
6. 可选：触发 Fabric 链上交易流程

注意：该流程计算量较大，Groth16/Plonk 阶段可能耗时较长。

## 可选：启用 Fabric 链上流程

默认不会执行链上调用。若要开启，请设置：

```bash
$env:FABRIC_ENABLE="1"
$env:FABRIC_MSP_ID="Org1MSP"
$env:FABRIC_PEER_ENDPOINT="localhost:7051"
$env:FABRIC_GATEWAY_PEER="peer0.org1.example.com"
$env:FABRIC_TLS_CERT=".\fabric-samples\test-network\organizations\peerOrganizations\org1.example.com\peers\peer0.org1.example.com\tls\ca.crt"
$env:FABRIC_CERT_PATH=".\fabric-samples\test-network\organizations\peerOrganizations\org1.example.com\users\User1@org1.example.com\msp\signcerts\User1@org1.example.com-cert.pem"
$env:FABRIC_KEY_PATH=".\fabric-samples\test-network\organizations\peerOrganizations\org1.example.com\users\User1@org1.example.com\msp\keystore\priv_sk"
$env:FABRIC_CHANNEL="mychannel"
$env:FABRIC_CHAINCODE="basic"
$env:FABRIC_SELLER_CLIENT_ID="eDUwOTo6Q049VXNlcjFAb3JnMS5leGFtcGxlLmNvbSxPVT1jbGllbnQsTD1TYW4gRnJhbmNpc2NvLFNUPUNhbGlmb3JuaWEsQz1VUzo6Q049Y2Eub3JnMS5leGFtcGxlLmNvbSxPPW9yZzEuZXhhbXBsZS5jb20sTD1TYW4gRnJhbmNpc2NvLFNUPUNhbGlmb3JuaWEsQz1VUw=="
```

可选参数（有默认值）：

- `FABRIC_TRADE_AMOUNT`（默认 `100`）
- `FABRIC_INIT_BALANCE`（默认 `1000`）
- `FABRIC_TRADE_TIMEOUT_SECONDS`（默认 `3600`）
- `FABRIC_TRADE_ID`（默认自动生成 `trade-{unix}`）

## 关键参数

- `ROUNDS = 110`
- `MAX_N = 1024`

对应位置：[src/shared.go](./src/shared.go)

## 主要产物文件

运行主流程后，默认会在 `data/` 下更新或生成：

- `encrypted_data.bin`
- `publicInputs.json`
- `witness.json`
- `proof.bin`
- `vk.bin`
- `pk.bin`
- `keyHash.json`（由 hash 相关逻辑生成）

## 相关文档

- [快速参考](./docs/快速参考.md)
- [模块化谓词设计](./docs/模块化谓词设计.md)
- [KeyHash电路设计](./docs/KeyHash电路设计.md)

## 备注

- 当前仓库中的中文注释/旧文档存在历史编码问题，本 README 已按 UTF-8 重写。
- `src/predicate.go` 中 `HashConsistencyCircuit` 仍为 TODO 实现。
