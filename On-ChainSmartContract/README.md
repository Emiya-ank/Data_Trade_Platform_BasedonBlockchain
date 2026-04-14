# On-chainSmartContract

本目录实现了一个基于 Hyperledger Fabric 的交易托管链码，核心特性：
- Buyer 锁定资金到托管账户（escrow）
- Seller 提交解密密钥并链上校验哈希
- 校验通过：资金结算给 Seller，并链上公布解密密钥
- 校验失败：资金自动退回 Buyer
- 超时后支持 Buyer 主动退款

## 1. 文件说明

- `src/chaincode.go`: 交易与托管核心逻辑
- `test/chaincode_test.go`: 核心工具函数单元测试（哈希/解析/规范化）
- `test/trade_flow_test.go`: 交易流程集成测试（成功结算/验证失败退款/超时退款）
- `go.mod`, `go.sum`: Go 模块依赖

## 2. 数据模型

链上交易结构 `Trade` 主要字段：
- `ID`: 交易 ID
- `Buyer`: 买家身份
- `Seller`: 卖家身份
- `Hash`: 密钥哈希（与 Off-ChainAgent 保持一致，Poseidon2 BN254）
- `Key`: 解密密钥（仅在验证通过后写入链上）
- `Status`: 交易状态
- `Amount`: 锁定/托管金额
- `Timeout`: 超时时间戳（Unix 秒）
- `CreateTime`: 创建时间戳
- `EndTime`:交易结束时间戳

## 3. 状态流转

- `INIT`: 交易已创建
- `LOCKED`: 资金已托管
- `DONE`: 验证通过，资金已结算给 Seller
- `REFUNDED`: 验证失败或超时退款

典型路径：
1. `INIT -> LOCKED -> DONE`
2. `INIT -> LOCKED -> REFUNDED`

## 4. 账本键设计

- `balance:<clientID>`: 用户可用余额
- `escrow:<tradeID>`: 交易托管余额

## 5. 公开合约接口

### 5.1 交易流程

0. `InitBalance(amount)`
- 初始化（或覆盖）调用者账户余额 `balance:<caller>`
- `amount` 必须为非负数

1. `CreateTrade(id, seller, timeout, hash)`
- 由 Buyer 创建交易
- `timeout` 为相对秒数，链上保存为 `Now()+timeout`

2. `LockTrade(id, amount)`
- 仅 Buyer 可调用
- 从 `balance:<buyer>` 扣款并增加 `escrow:<id>`
- 状态 `INIT -> LOCKED`

3. `SubmitKeyandVerify(id, key)`
- 仅 Seller 可调用
- 对 `key` 执行 Poseidon2(BN254, key.Bytes()) 并与 `Trade.Hash` 比较
- 校验通过：
  - `escrow` 资金转入 `balance:<seller>`
  - `Trade.Key = key`（链上公布解密密钥）
  - 状态改为 `DONE`
- 校验失败：
  - `escrow` 资金退回 `balance:<buyer>`
  - 状态改为 `REFUNDED`

4. `RefundTrade(id)`
- 仅 Buyer 可调用
- 要求状态为 `LOCKED` 且已超时（`Now() > Timeout`）
- `escrow` 资金退回 Buyer，状态改为 `REFUNDED`

### 5.2 查询接口

- `GetTrade(id)`：查询完整交易信息
- `QueryEscrow(id)`：查询托管余额
- `QueryBalance(clientID)`：查询账户可用余额

## 6. 哈希一致性说明（与 Off-ChainAgent 对齐）

链上 `SubmitKeyandVerify` 使用：
- 算法：`Poseidon2_BN254`
- 输入：`key` 解析为 `big.Int` 后取 `Bytes()`
- 输出：十六进制字符串，与 `Trade.Hash` 比较（忽略大小写，支持 `0x` 前缀）

这与 Off-ChainAgent 中 `KeyPoseidonHash(key *big.Int)` 保持一致。

## 7. 本地构建与测试

在本目录执行：

```powershell
go mod tidy
go test ./...
```

当前预期输出：
- `go test` 会执行 `test/chaincode_test.go`，并通过

可选：仅运行新增测试文件

```powershell
go test ./test -v
```

重点流程测试（推荐）：
- `TestTradeFlowSuccess`: `CreateTrade -> LockTrade -> SubmitKeyandVerify(通过) -> Seller 收款`
- `TestTradeFlowVerifyFailRefundToBuyer`: `SubmitKeyandVerify(不通过) -> Buyer 自动退款`
- `TestTradeFlowTimeoutRefund`: `LOCKED 且超时 -> RefundTrade -> Buyer 退款`

## 8. 注意事项

- 当前为最小实现，默认信任链上调用身份系统。
- `SubmitKeyandVerify` 会在成功时公开 `Trade.Key`，请确认该行为符合你的业务隐私要求。
- 建议在上层应用中补充初始化余额、权限审计和事件通知。
