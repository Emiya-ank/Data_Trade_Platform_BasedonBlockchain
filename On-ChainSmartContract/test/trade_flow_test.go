package smartcontract_test

import (
	"crypto/x509"
	"fmt"
	"testing"

	smartcontract "chaincode/src"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// mockClientIdentity 用于在测试中注入可控的调用者身份。
type mockClientIdentity struct {
	id string
}

func (m *mockClientIdentity) GetID() (string, error) {
	return m.id, nil
}

func (m *mockClientIdentity) GetMSPID() (string, error) {
	return "Org1MSP", nil
}

func (m *mockClientIdentity) GetAttributeValue(attrName string) (value string, found bool, err error) {
	return "", false, nil
}

func (m *mockClientIdentity) AssertAttributeValue(attrName, attrValue string) error {
	return nil
}

func (m *mockClientIdentity) GetX509Certificate() (*x509.Certificate, error) {
	return nil, nil
}

// newTxContext 创建测试交易上下文，并绑定 stub 与调用者身份。
func newTxContext(stub *shimtest.MockStub, clientID string) *contractapi.TransactionContext {
	ctx := new(contractapi.TransactionContext)
	ctx.SetStub(stub)
	ctx.SetClientIdentity(&mockClientIdentity{id: clientID})
	return ctx
}

// withTx 将一次合约调用包装在 Mock 交易生命周期中。
func withTx(stub *shimtest.MockStub, txID string, fn func() error) error {
	stub.MockTransactionStart(txID)
	defer stub.MockTransactionEnd(txID)
	return fn()
}

// mustNoErr 遇到异常立即失败，减少重复错误处理代码。
func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// setupTradeHash 根据测试 key 生成链上期望哈希。
func setupTradeHash(t *testing.T, key string) string {
	t.Helper()
	keyInt, err := smartcontract.ParseBigIntKey(key)
	mustNoErr(t, err)
	hash, err := smartcontract.Poseidon2BN254HashHexFromBigInt(keyInt)
	mustNoErr(t, err)
	return hash
}

// putBalance 预置测试账户余额。
func putBalance(t *testing.T, stub *shimtest.MockStub, clientID string, amount int64) {
	t.Helper()
	ctx := newTxContext(stub, clientID)
	err := withTx(stub, fmt.Sprintf("tx-put-balance-%s", clientID), func() error {
		return smartcontract.PutInt64State(ctx, smartcontract.BalanceKey(clientID), amount)
	})
	mustNoErr(t, err)
}

// getBalance 通过合约公开接口读取账户余额。
func getBalance(t *testing.T, sc *smartcontract.SmartContract, ctx contractapi.TransactionContextInterface, clientID string) int64 {
	t.Helper()
	v, err := sc.QueryBalance(ctx, clientID)
	mustNoErr(t, err)
	return v
}

// getEscrow 通过合约公开接口读取托管余额。
func getEscrow(t *testing.T, sc *smartcontract.SmartContract, ctx contractapi.TransactionContextInterface, id string) int64 {
	t.Helper()
	v, err := sc.QueryEscrow(ctx, id)
	mustNoErr(t, err)
	return v
}

// TestTradeFlowSuccess 覆盖成功路径：
// 创建交易 -> 锁定资金 -> 密钥验证通过 -> 卖家收款并链上公布密钥。
func TestTradeFlowSuccess(t *testing.T) {
	sc := new(smartcontract.SmartContract)
	stub := shimtest.NewMockStub("trade-flow-success", nil)
	buyerID := "buyerA"
	sellerID := "sellerA"
	tradeID := "trade-success-1"
	key := "19"
	hash := setupTradeHash(t, key)

	putBalance(t, stub, buyerID, 1000)

	buyerCtx := newTxContext(stub, buyerID)
	sellerCtx := newTxContext(stub, sellerID)

	mustNoErr(t, withTx(stub, "tx-create", func() error {
		return sc.CreateTrade(buyerCtx, tradeID, sellerID, 3600, hash)
	}))
	mustNoErr(t, withTx(stub, "tx-lock", func() error {
		return sc.LockTrade(buyerCtx, tradeID, 300)
	}))
	mustNoErr(t, withTx(stub, "tx-submit-success", func() error {
		return sc.SubmitKeyandVerify(sellerCtx, tradeID, key)
	}))

	trade, err := sc.GetTrade(sellerCtx, tradeID)
	mustNoErr(t, err)
	if trade.Status != smartcontract.StatusDone {
		t.Fatalf("status mismatch, got=%s want=%s", trade.Status, smartcontract.StatusDone)
	}
	if trade.Key != key {
		t.Fatalf("key mismatch, got=%s want=%s", trade.Key, key)
	}
	if getBalance(t, sc, sellerCtx, sellerID) != 300 {
		t.Fatalf("seller balance mismatch")
	}
	if getBalance(t, sc, buyerCtx, buyerID) != 700 {
		t.Fatalf("buyer balance mismatch")
	}
	if getEscrow(t, sc, sellerCtx, tradeID) != 0 {
		t.Fatalf("escrow should be zero after settlement")
	}
}

// TestTradeFlowVerifyFailRefundToBuyer 覆盖校验失败路径：
// 密钥校验不通过，托管资金自动退回买家。
func TestTradeFlowVerifyFailRefundToBuyer(t *testing.T) {
	sc := new(smartcontract.SmartContract)
	stub := shimtest.NewMockStub("trade-flow-fail", nil)
	buyerID := "buyerB"
	sellerID := "sellerB"
	tradeID := "trade-fail-1"
	hash := setupTradeHash(t, "19")

	putBalance(t, stub, buyerID, 1000)

	buyerCtx := newTxContext(stub, buyerID)
	sellerCtx := newTxContext(stub, sellerID)

	mustNoErr(t, withTx(stub, "tx2-create", func() error {
		return sc.CreateTrade(buyerCtx, tradeID, sellerID, 3600, hash)
	}))
	mustNoErr(t, withTx(stub, "tx2-lock", func() error {
		return sc.LockTrade(buyerCtx, tradeID, 300)
	}))
	mustNoErr(t, withTx(stub, "tx2-submit-fail", func() error {
		return sc.SubmitKeyandVerify(sellerCtx, tradeID, "20")
	}))

	trade, err := sc.GetTrade(sellerCtx, tradeID)
	mustNoErr(t, err)
	if trade.Status != smartcontract.StatusRefunded {
		t.Fatalf("status mismatch, got=%s want=%s", trade.Status, smartcontract.StatusRefunded)
	}
	if trade.Key != "" {
		t.Fatalf("key should not be published on verify failure")
	}
	if getBalance(t, sc, sellerCtx, sellerID) != 0 {
		t.Fatalf("seller balance should stay zero")
	}
	if getBalance(t, sc, buyerCtx, buyerID) != 1000 {
		t.Fatalf("buyer should be refunded to original balance")
	}
	if getEscrow(t, sc, buyerCtx, tradeID) != 0 {
		t.Fatalf("escrow should be zero after refund")
	}
}

// TestTradeFlowTimeoutRefund 覆盖超时退款路径：
// 交易锁定后超时，买家可调用 RefundTrade 取回托管资金。
func TestTradeFlowTimeoutRefund(t *testing.T) {
	sc := new(smartcontract.SmartContract)
	stub := shimtest.NewMockStub("trade-flow-timeout", nil)
	buyerID := "buyerC"
	sellerID := "sellerC"
	tradeID := "trade-timeout-1"
	hash := setupTradeHash(t, "19")

	putBalance(t, stub, buyerID, 500)

	buyerCtx := newTxContext(stub, buyerID)

	// timeout=-1 表示创建后立即满足超时条件。
	mustNoErr(t, withTx(stub, "tx3-create", func() error {
		return sc.CreateTrade(buyerCtx, tradeID, sellerID, -1, hash)
	}))
	mustNoErr(t, withTx(stub, "tx3-lock", func() error {
		return sc.LockTrade(buyerCtx, tradeID, 200)
	}))
	mustNoErr(t, withTx(stub, "tx3-refund", func() error {
		return sc.RefundTrade(buyerCtx, tradeID)
	}))

	trade, err := sc.GetTrade(buyerCtx, tradeID)
	mustNoErr(t, err)
	if trade.Status != smartcontract.StatusRefunded {
		t.Fatalf("status mismatch, got=%s want=%s", trade.Status, smartcontract.StatusRefunded)
	}
	if getBalance(t, sc, buyerCtx, buyerID) != 500 {
		t.Fatalf("buyer should be refunded to original balance")
	}
	if getEscrow(t, sc, buyerCtx, tradeID) != 0 {
		t.Fatalf("escrow should be zero after timeout refund")
	}
}

// TestInitBalance 覆盖余额初始化接口：
// 1) 正常设置余额
// 2) 非法负数金额应报错
func TestInitBalance(t *testing.T) {
	sc := new(smartcontract.SmartContract)
	stub := shimtest.NewMockStub("trade-init-balance", nil)
	userID := "buyer-init"
	ctx := newTxContext(stub, userID)

	mustNoErr(t, withTx(stub, "tx-init-balance", func() error {
		return sc.InitBalance(ctx, 1234)
	}))

	if got := getBalance(t, sc, ctx, userID); got != 1234 {
		t.Fatalf("balance mismatch, got=%d want=%d", got, 1234)
	}

	err := withTx(stub, "tx-init-balance-negative", func() error {
		return sc.InitBalance(ctx, -1)
	})
	if err == nil {
		t.Fatalf("expected error for negative amount")
	}
}

// 编译期接口检查：mockClientIdentity 必须实现 cid.ClientIdentity。
var _ cid.ClientIdentity = (*mockClientIdentity)(nil)
