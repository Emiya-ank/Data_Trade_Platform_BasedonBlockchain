package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const MAX_M = 5

// BN254 标量域
var modulus, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617",
	10,
)

// =====================
// 工具函数
// =====================
func mod(x *big.Int) *big.Int {
	return new(big.Int).Mod(x, modulus)
}

// =====================
// 电路定义
// =====================
type MyCTRMiMCCircuit struct {
	Plaintext  [MAX_M]frontend.Variable
	Ciphertext [MAX_M]frontend.Variable
	Selector   [MAX_M]frontend.Variable
	TextLen    frontend.Variable
	Key        frontend.Variable
	Nonce      frontend.Variable
}

// =====================
// 电路内 MiMC（必须和链下一致）
// =====================
func mimcHash(api frontend.API, x, key frontend.Variable) frontend.Variable {
	h := api.Add(x, key)

	for i := 0; i < 10; i++ {
		h = api.Add(h, i+1)

		h2 := api.Mul(h, h)
		h3 := api.Mul(h2, h)
		h6 := api.Mul(h3, h3)
		h = api.Mul(h6, h)
	}
	return h
}

// =====================
// 电路约束
// =====================
func (c *MyCTRMiMCCircuit) Define(api frontend.API) error {

	for i := 0; i < MAX_M; i++ {

		// selector ∈ {0,1}
		api.AssertIsBoolean(c.Selector[i])

		// 单调性：1...1,0...0
		if i > 0 {
			api.AssertIsLessOrEqual(c.Selector[i], c.Selector[i-1])
		}

		// CTR
		ctr := api.Add(c.Nonce, i)
		ks := mimcHash(api, ctr, c.Key)

		// 加密
		validCipher := api.Add(c.Plaintext[i], ks)

		expected := api.Mul(c.Selector[i], validCipher)

		api.AssertIsEqual(c.Ciphertext[i], expected)

		// padding 区 plaintext 必须为 0
		padding := api.Sub(1, c.Selector[i])
		api.AssertIsEqual(api.Mul(padding, c.Plaintext[i]), 0)
	}

	return nil
}

// =====================
// 链下 MiMC（big.Int 版本）
// =====================
func mimcHashNative(x, key *big.Int) *big.Int {

	h := mod(new(big.Int).Add(x, key))

	for i := 0; i < 10; i++ {

		h = mod(new(big.Int).Add(h, big.NewInt(int64(i+1))))

		h2 := mod(new(big.Int).Mul(h, h))
		h3 := mod(new(big.Int).Mul(h2, h))
		h6 := mod(new(big.Int).Mul(h3, h3))
		h = mod(new(big.Int).Mul(h6, h))
	}

	return h
}

// =====================
// 生成 ciphertext（链下）
// =====================
func genCiphertext(pt []int, key, nonce int) []*big.Int {

	ct := make([]*big.Int, len(pt))

	keyBig := big.NewInt(int64(key))
	nonceBig := big.NewInt(int64(nonce))

	for i := 0; i < len(pt); i++ {

		ptBig := big.NewInt(int64(pt[i]))
		ctr := new(big.Int).Add(nonceBig, big.NewInt(int64(i)))

		ks := mimcHashNative(ctr, keyBig)

		ct[i] = mod(new(big.Int).Add(ptBig, ks))
	}

	return ct
}

// =====================
// main
// =====================
// func main() {
func Demo() {

	// 1️⃣ 编译电路
	var circuit MyCTRMiMCCircuit

	r1cs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&circuit,
	)
	if err != nil {
		panic(err)
	}

	// 2️⃣ setup
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// 3️⃣ 输入
	pt := []int{10, 20, 30}
	key := 3
	nonce := 7

	ct := genCiphertext(pt, key, nonce)

	fmt.Println("plaintext :", pt)
	fmt.Println("ciphertext:", ct)

	// 4️⃣ 构造 witness
	var w MyCTRMiMCCircuit

	w.Key = big.NewInt(int64(key))
	w.Nonce = big.NewInt(int64(nonce))

	for i := 0; i < MAX_M; i++ {

		if i < len(pt) {
			w.Plaintext[i] = big.NewInt(int64(pt[i]))
			w.Ciphertext[i] = ct[i]
			w.Selector[i] = 1
		} else {
			w.Plaintext[i] = 0
			w.Ciphertext[i] = 0
			w.Selector[i] = 0
		}
	}

	// 5️⃣ witness
	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	// 6️⃣ prove
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	// 7️⃣ verify
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	fmt.Println("✅ Verify SUCCESS")
}
