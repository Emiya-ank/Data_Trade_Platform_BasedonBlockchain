package smartcontract_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	gchash "github.com/consensys/gnark-crypto/hash"

	smartcontract "chaincode/src"
)

// TestNormalizeHash 验证哈希规范化规则：
// 去除首尾空格、去掉可选 0x 前缀、统一转小写。
func TestNormalizeHash(t *testing.T) {
	got := smartcontract.NormalizeHash("  0xAbCdEF  ")
	want := "abcdef"
	if got != want {
		t.Fatalf("NormalizeHash mismatch, got=%q want=%q", got, want)
	}
}

// TestParseBigIntKey 验证密钥字符串解析逻辑及异常输入处理。
func TestParseBigIntKey(t *testing.T) {
	// 十进制输入应能正确解析。
	t.Run("decimal", func(t *testing.T) {
		v, err := smartcontract.ParseBigIntKey("19")
		if err != nil {
			t.Fatalf("ParseBigIntKey decimal failed: %v", err)
		}
		if v.Cmp(big.NewInt(19)) != 0 {
			t.Fatalf("unexpected decimal value: %s", v.String())
		}
	})

	// 带 0x 前缀的十六进制输入应解析为同一数值。
	t.Run("hex", func(t *testing.T) {
		v, err := smartcontract.ParseBigIntKey("0x13")
		if err != nil {
			t.Fatalf("ParseBigIntKey hex failed: %v", err)
		}
		if v.Cmp(big.NewInt(19)) != 0 {
			t.Fatalf("unexpected hex value: %s", v.String())
		}
	})

	// 负数应被拒绝。
	t.Run("negative rejected", func(t *testing.T) {
		if _, err := smartcontract.ParseBigIntKey("-1"); err == nil {
			t.Fatal("expected error for negative key, got nil")
		}
	})

	// 非数字字符串应被拒绝。
	t.Run("invalid rejected", func(t *testing.T) {
		if _, err := smartcontract.ParseBigIntKey("not-a-number"); err == nil {
			t.Fatal("expected error for invalid key, got nil")
		}
	})
}

// TestPoseidon2BN254HashHexFromBigInt 验证合约哈希函数
// 与 gnark-crypto Poseidon2(BN254) 基准实现一致。
func TestPoseidon2BN254HashHexFromBigInt(t *testing.T) {
	key := big.NewInt(19)

	got, err := smartcontract.Poseidon2BN254HashHexFromBigInt(key)
	if err != nil {
		t.Fatalf("Poseidon2BN254HashHexFromBigInt failed: %v", err)
	}

	h := gchash.POSEIDON2_BN254.New()
	if _, err := h.Write(key.Bytes()); err != nil {
		t.Fatalf("baseline hash write failed: %v", err)
	}
	want := hex.EncodeToString(h.Sum(nil))

	if got != want {
		t.Fatalf("hash mismatch, got=%s want=%s", got, want)
	}
}
