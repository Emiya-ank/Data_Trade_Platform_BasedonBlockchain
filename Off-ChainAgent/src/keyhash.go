package offchain

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
)

// 密钥哈希定义
type KH struct {
	KeyHash string
}

// 计算密钥哈希
func KeyPoseidonHash(key *big.Int) []byte {
	poseidon2 := Poseidon2CaseMap["BN254"].Hash
	hashresult := Poseidon2Hash(poseidon2, key)

	return hashresult
}

// 导出密钥哈希 keyHash.json
func ExportKeyHash(keyhash []byte, path string) error {
	data := KH{
		KeyHash: hex.EncodeToString(keyhash),
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, jsonBytes, 0644)
}
