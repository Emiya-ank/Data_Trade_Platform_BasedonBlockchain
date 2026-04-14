package main

import (
	"fmt"
	"math/big"
	offchain "Off-ChainAgent/src"
)

// func main() {
func HashTest() {
	path := "./data/keyHash.json"
	key := big.NewInt(19)

	// 计算密钥哈希
	keyHash := offchain.KeyPoseidonHash(key)
	// 导出密钥哈希
	err := offchain.ExportKeyHash(keyHash, path)
	if err != nil {
		panic(err)
	}
	fmt.Printf("密钥哈希计算并导出成功！路径：%s\n", path)
}
