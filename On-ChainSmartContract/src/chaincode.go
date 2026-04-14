package smartcontract

import (
	"encoding/json"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	gchash "github.com/consensys/gnark-crypto/hash"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

// 交易状态
const (
	StatusInit      = "INIT"
	StatusLocker    = "LOCKED"
	StatusDelivered = "DELIVERED"
	StatusDone      = "DONE"
	StatusRefunded  = "REFUNDED"
)

// World state 键前缀约定:
// 1) balance:<clientID> 记录用户可用余额
// 2) escrow:<tradeID>   记录该交易托管资金余额
const (
	balanceKeyPrefix = "balance:"
	escrowKeyPrefix  = "escrow:"
)

// Trade 表示一笔哈希锁交易记录。
// Status 典型流转: INIT -> LOCKED -> DELIVERED -> DONE
// 超时或异常可进入 REFUNDED。
type Trade struct {
	ID         string `json:"id"`
	Buyer      string `json:"buyer"`
	Seller     string `json:"seller"`
	Key        string `json:"key"`        // 加密密钥
	Hash       string `json:"hash"`       // 密钥哈希
	Status     string `json:"status"`     // 交易状态
	Amount     int64  `json:"amount"`     // 交易资金金额
	Timeout    int64  `json:"timeout"`    // 交易超时时间
	CreateTime int64  `json:"createTime"` // 交易创建时间
	EndTime    int64  `json:"endTime"`    // 交易结束时间
}

// 获取调用者的身份
func GetClientID(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", err
	}
	return id, nil
}

// 获取交易状态
func (s *SmartContract) GetTrade(ctx contractapi.TransactionContextInterface, id string) (*Trade, error) {
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("Trade Not Found!")
	}
	var trade Trade
	err = json.Unmarshal(data, &trade)
	if err != nil {
		return nil, err
	}
	return &trade, nil
}

// 存储交易状态
func (s *SmartContract) PutTrade(ctx contractapi.TransactionContextInterface, trade *Trade) error {
	data, err := json.Marshal(trade)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(trade.ID, data)
}

// 获取当前时间戳
func Now() int64 {
	return time.Now().Unix()
}

// BalanceKey 生成用户余额键。
func BalanceKey(clientID string) string {
	return balanceKeyPrefix + clientID
}

// escrowKey 生成交易托管余额键。
func EscrowKey(tradeID string) string {
	return escrowKeyPrefix + tradeID
}

// GetInt64State 读取 int64 数值状态。
// 约定: 键不存在返回 0，不视为错误。
func GetInt64State(ctx contractapi.TransactionContextInterface, key string) (int64, error) {
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, nil
	}

	v, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid int64 state for key %s: %w", key, err)
	}
	return v, nil
}

// PutInt64State 以十进制字符串形式写入 int64 状态。
func PutInt64State(ctx contractapi.TransactionContextInterface, key string, value int64) error {
	return ctx.GetStub().PutState(key, []byte(strconv.FormatInt(value, 10)))
}

// InitBalance 初始化（或覆盖）调用者的可用余额。
// 说明:
// 1) 仅作用于交易调用者自身账户 balance:<clientID>
// 2) amount 必须为非负数
func (s *SmartContract) InitBalance(ctx contractapi.TransactionContextInterface, amount int64) error {
	if amount < 0 {
		return fmt.Errorf("amount must be non-negative")
	}

	clientID, err := GetClientID(ctx)
	if err != nil {
		return err
	}

	return PutInt64State(ctx, BalanceKey(clientID), amount)
}

// CreateTrade 由 Buyer 创建交易。
func (s *SmartContract) CreateTrade(ctx contractapi.TransactionContextInterface, id string, seller string, timeout int64, hash string) error {
	buyer, err := GetClientID(ctx)
	if err != nil {
		return err
	}

	exist, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	if exist != nil {
		return fmt.Errorf("Trade Already Exsist!")
	}

	trade := Trade{
		ID:         id,
		Buyer:      buyer,
		Seller:     seller,
		Status:     StatusInit,
		Hash:       hash,
		CreateTime: Now(),
		Timeout:    Now() + timeout,
	}

	return s.PutTrade(ctx, &trade)
}

// LockTrade 由 Buyer 锁定交易资金并托管到 escrow。
// 核心步骤:
// 1) 校验调用者必须是该交易 Buyer
// 2) 校验交易状态必须为 INIT
// 3) 校验 amount > 0 且 Buyer 余额充足
// 4) 扣减 Buyer 可用余额, 增加 escrow:<tradeID> 托管余额
// 5) 更新交易状态为 LOCKED 并记录锁定金额
func (s *SmartContract) LockTrade(ctx contractapi.TransactionContextInterface, id string, amount int64) error {
	trade, err := s.GetTrade(ctx, id)
	if err != nil {
		return err
	}

	buyer, err := GetClientID(ctx)
	if err != nil {
		return err
	}
	if trade.Buyer != buyer {
		return fmt.Errorf("only buyer can lock trade")
	}

	if trade.Status != StatusInit {
		return fmt.Errorf("Trade Status Error!")
	}
	if amount <= 0 {
		return fmt.Errorf("amount must be positive")
	}

	buyerBalanceKey := BalanceKey(buyer)
	buyerBalance, err := GetInt64State(ctx, buyerBalanceKey)
	if err != nil {
		return err
	}
	if buyerBalance < amount {
		return fmt.Errorf("insufficient balance: current=%d, required=%d", buyerBalance, amount)
	}

	// 资金托管: 买家余额扣减, 交易托管余额增加
	escrowBalanceKey := EscrowKey(id)
	escrowBalance, err := GetInt64State(ctx, escrowBalanceKey)
	if err != nil {
		return err
	}
	if err := PutInt64State(ctx, buyerBalanceKey, buyerBalance-amount); err != nil {
		return err
	}
	if err := PutInt64State(ctx, escrowBalanceKey, escrowBalance+amount); err != nil {
		return err
	}

	trade.Status = StatusLocker
	trade.Amount = escrowBalance + amount
	return s.PutTrade(ctx, trade)
}

// NormalizeHash 规范化哈希字符串，去除 "0x" 前缀并转换为小写，方便比较。
func NormalizeHash(h string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(h)), "0x")
}

// ParseBigIntKey 将输入字符串解析为 *big.Int，支持十进制和十六进制格式，并验证非负性。
func ParseBigIntKey(key string) (*big.Int, error) {
	k := strings.TrimSpace(key)
	if k == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	v := new(big.Int)
	base := 10
	if strings.HasPrefix(strings.ToLower(k), "0x") {
		base = 0
	}
	if _, ok := v.SetString(k, base); !ok {
		return nil, fmt.Errorf("key must be a valid integer string")
	}
	if v.Sign() < 0 {
		return nil, fmt.Errorf("key must be non-negative")
	}

	return v, nil
}

// Poseidon2BN254HashHexFromBigInt 计算 Poseidon2(BN254) 哈希并返回十六进制字符串。
func Poseidon2BN254HashHexFromBigInt(v *big.Int) (string, error) {
	h := gchash.POSEIDON2_BN254.New()
	if _, err := h.Write(v.Bytes()); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SubmitKey 由 Seller 提交密钥并触发托管资金结算。
// 核心步骤:
// 1) 校验调用者是 Seller 且交易状态为 LOCKED
// 2) 校验当前未超时, 并验证 Poseidon2(BN254, key.Bytes()) 与 trade.Hash 一致
// 3) 若验证通过: escrow 资金转入 Seller, 状态改为 DONE, 并上链保存解密密钥
// 4) 若验证失败: escrow 资金退回 Buyer, 状态改为 REFUNDED
func (s *SmartContract) SubmitKeyandVerify(ctx contractapi.TransactionContextInterface, id string, key string) error {
	trade, err := s.GetTrade(ctx, id)
	if err != nil {
		return err
	}

	seller, err := GetClientID(ctx)
	if err != nil {
		return err
	}
	if trade.Seller != seller {
		return fmt.Errorf("only seller can submit key")
	}

	if trade.Status != StatusLocker {
		return fmt.Errorf("Trade Status Error!")
	}
	if Now() > trade.Timeout {
		return fmt.Errorf("trade has timed out")
	}

	escrowBalanceKey := EscrowKey(id)
	escrowAmount, err := GetInt64State(ctx, escrowBalanceKey)
	if err != nil {
		return err
	}
	if escrowAmount <= 0 {
		return fmt.Errorf("no escrow funds for trade")
	}

	keyBigInt, err := ParseBigIntKey(key)
	if err != nil {
		return err
	}
	calculatedHash, err := Poseidon2BN254HashHexFromBigInt(keyBigInt)
	if err != nil {
		return err
	}
	if NormalizeHash(calculatedHash) == NormalizeHash(trade.Hash) {
		sellerBalanceKey := BalanceKey(seller)
		sellerBalance, err := GetInt64State(ctx, sellerBalanceKey)
		if err != nil {
			return err
		}
		if err := PutInt64State(ctx, sellerBalanceKey, sellerBalance+escrowAmount); err != nil {
			return err
		}
		if err := PutInt64State(ctx, escrowBalanceKey, 0); err != nil {
			return err
		}

		trade.Key = key
		trade.EndTime = Now()
		trade.Status = StatusDone
		if trade.Amount == 0 {
			trade.Amount = escrowAmount
		}
		return s.PutTrade(ctx, trade)
	}

	buyerBalanceKey := BalanceKey(trade.Buyer)
	buyerBalance, err := GetInt64State(ctx, buyerBalanceKey)
	if err != nil {
		return err
	}
	if err := PutInt64State(ctx, buyerBalanceKey, buyerBalance+escrowAmount); err != nil {
		return err
	}
	if err := PutInt64State(ctx, escrowBalanceKey, 0); err != nil {
		return err
	}

	trade.Key = ""
	trade.EndTime = Now()
	trade.Status = StatusRefunded
	if trade.Amount == 0 {
		trade.Amount = escrowAmount
	}
	return s.PutTrade(ctx, trade)
}

// RefundTrade 处理超时退款:
// 1) 仅 Buyer 可调用
// 2) 仅 LOCKED 状态可退款
// 3) 当前时间超过 Timeout 后, escrow 资金退回 Buyer
// 4) 交易状态更新为 REFUNDED
func (s *SmartContract) RefundTrade(ctx contractapi.TransactionContextInterface, id string) error {
	trade, err := s.GetTrade(ctx, id)
	if err != nil {
		return err
	}

	buyer, err := GetClientID(ctx)
	if err != nil {
		return err
	}
	if trade.Buyer != buyer {
		return fmt.Errorf("only buyer can refund timed-out trade")
	}

	if trade.Status != StatusLocker {
		return fmt.Errorf("only locked trade can be refunded")
	}
	if Now() <= trade.Timeout {
		return fmt.Errorf("trade has not timed out")
	}

	escrowBalanceKey := EscrowKey(id)
	escrowAmount, err := GetInt64State(ctx, escrowBalanceKey)
	if err != nil {
		return err
	}
	if escrowAmount <= 0 {
		return fmt.Errorf("no escrow funds for trade")
	}

	buyerBalanceKey := BalanceKey(trade.Buyer)
	buyerBalance, err := GetInt64State(ctx, buyerBalanceKey)
	if err != nil {
		return err
	}
	if err := PutInt64State(ctx, buyerBalanceKey, buyerBalance+escrowAmount); err != nil {
		return err
	}
	if err := PutInt64State(ctx, escrowBalanceKey, 0); err != nil {
		return err
	}

	trade.Key = ""
	trade.EndTime = Now()
	trade.Status = StatusRefunded
	if trade.Amount == 0 {
		trade.Amount = escrowAmount
	}
	return s.PutTrade(ctx, trade)
}

// QueryEscrow 查询指定交易当前托管余额。
func (s *SmartContract) QueryEscrow(ctx contractapi.TransactionContextInterface, id string) (int64, error) {
	return GetInt64State(ctx, EscrowKey(id))
}

// QueryBalance 查询指定 clientID 的可用余额。
func (s *SmartContract) QueryBalance(ctx contractapi.TransactionContextInterface, clientID string) (int64, error) {
	return GetInt64State(ctx, BalanceKey(clientID))
}
