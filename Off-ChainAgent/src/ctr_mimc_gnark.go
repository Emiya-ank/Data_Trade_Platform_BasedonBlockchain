package offchain

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	_ "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	_ "github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash"
	stdposeidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
	_ "github.com/consensys/gnark/test/unsafekzg"
	"golang.org/x/crypto/sha3"
)

// 返回 1 当 x <= y，否则返回 0
func LessOrEqual(api frontend.API, x, y interface{}, bits int) frontend.Variable {
	xx := api.Sub(y, x) // y - x >= 0 ?

	// 分解成 bits 位二进制，最高位是符号位
	bin := api.ToBinary(xx, bits)

	// 确保最高位为 0 → 非负
	// 返回 1 表示 ok, 0 表示失败
	return api.IsZero(bin[bits-1])
}

// 轮函数 x = (x + k + c_i) ^ d, 设置指数 d = 5
// 计算指数为 5 的乘方
func Pow5(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)   // x^2
	x3 := api.Mul(x2, x)  // x^3
	x5 := api.Mul(x2, x3) // x^5
	return x5
}

// 生成轮常量
func RoundConstants() []frontend.Variable {
	rc := make([]frontend.Variable, ROUNDS)

	var seed [32]byte
	seed = sha3.Sum256(seed[:]) // c_0 = Keccak256(0)

	p := fr.Modulus()

	for i := 0; i < ROUNDS; i++ {
		seed = sha3.Sum256(seed[:])
		hashValue := new(big.Int).SetBytes(seed[:])
		rc[i] = new(big.Int).Mod(hashValue, p)
	}

	return rc
}

// 轮函数实现
func RoundFunction(api frontend.API, x frontend.Variable, key frontend.Variable, rc []frontend.Variable) frontend.Variable {
	state := x

	for i := 0; i < ROUNDS; i++ {
		// x = (x + k + c_i) ^ d
		state = api.Add(state, key, rc[i])
		state = Pow5(api, state)
	}
	return state
}

// Pedersen 承诺生成元
func PedersenGenerators() []frontend.Variable {
	generators := make([]frontend.Variable, MAX_N+1)

	var seed [32]byte
	seed = sha3.Sum256([]byte("pedersen-generators"))
	modulus := fr.Modulus()

	for i := 0; i < MAX_N+1; i++ {
		seed = sha3.Sum256(seed[:])
		generators[i] = new(big.Int).Mod(new(big.Int).SetBytes(seed[:]), modulus)
		if generators[i] == 0 {
			generators[i] = big.NewInt(1)
		}
	}

	return generators
}

// CTR 模式下 MiMC 密码电路结构定义
type CTRMiMCCircuit struct {
	Plaintext  [MAX_N]frontend.Variable //明文
	Ciphertext [MAX_N]frontend.Variable //密文
	TextLen    frontend.Variable        //明文实际长度
	Selector   [MAX_N]frontend.Variable //选择器：1 表示有效位，0 表示填充位
	Key        frontend.Variable        //加密密钥
	KeyHash    frontend.Variable        //密钥哈希（公开输入）
	Nonce      frontend.Variable        //密钥流偏移量（有限域上的随机数）
	Commitment frontend.Variable        //Pedersen 承诺值
	Randomness frontend.Variable        //Pedersen 承诺的随机数
	C1     sw_bn254.G1Affine `gnark:",public"`	//ElGamal 密文 C1 = r*G
	C2     sw_bn254.G1Affine `gnark:",public"` 	//ElGamal 密文 C2 = M + r*Pubkey
	Pubkey sw_bn254.G1Affine `gnark:",public"`	//ElGamal 公钥 Pubkey = s*G

	R sw_bn254.Scalar    //ElGamal 随机数 r
	M sw_bn254.G1Affine  //ElGamal 明文 M
}

// CTR 模式下 MiMC 密码电路逻辑定义
func (c *CTRMiMCCircuit) Define(api frontend.API) error {

	// 密钥 Poseidon2 哈希约束
	params := poseidon2_bn254.GetDefaultParameters()
	perm, err := stdposeidon2.NewPoseidon2FromParameters(api, 2, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return err
	}
	poseidonHasher := hash.NewMerkleDamgardHasher(api, perm, 0)

	poseidonHasher.Write(c.Key)
	computedKeyHash := poseidonHasher.Sum()
	api.AssertIsEqual(computedKeyHash, c.KeyHash)

	// MiMC 加密电路约束
	rc := RoundConstants()

	for i := 0; i < MAX_N; i++ {
		api.AssertIsBoolean(c.Selector[i])

		if i > 0 {
			api.AssertIsLessOrEqual(c.Selector[i], c.Selector[i-1])
		}

		ctr := api.Add(c.Nonce, i)
		ks := RoundFunction(api, ctr, c.Key, rc)

		validcipher := api.Add(c.Plaintext[i], ks)
		expected := api.Mul(c.Selector[i], validcipher)
		api.AssertIsEqual(c.Ciphertext[i], expected)

		padding := api.Sub(1, c.Selector[i])
		api.AssertIsEqual(api.Mul(padding, c.Plaintext[i]), 0)
	}

	// Pedersen 承诺电路约束
	sum := frontend.Variable(0)
	generators := PedersenGenerators()
	for i := 0; i < MAX_N; i++ {
		cmp := api.Cmp(c.TextLen, i+1)
		isGt := api.IsZero(api.Sub(cmp, 1))
		isEq := api.IsZero(cmp)
		si := api.Add(isGt, isEq)
		term := api.Mul(c.Plaintext[i], generators[i])
		term = api.Mul(term, si)
		sum = api.Add(sum, term)
	}

	H := generators[MAX_N]
	randomTerm := api.Mul(c.Randomness, H)
	sum = api.Add(sum, randomTerm)
	api.AssertIsEqual(c.Commitment, sum)

	// ElGamal 加密电路约束
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}

	curve.AssertIsOnCurve(&c.C1)
	curve.AssertIsOnCurve(&c.C2)
	curve.AssertIsOnCurve(&c.Pubkey)
	curve.AssertIsOnCurve(&c.M)

	rG := curve.ScalarMulBase(&c.R)
	curve.AssertIsEqual(&c.C1, rG)

	rPubkey := curve.ScalarMul(&c.Pubkey, &c.R)
	expectedC2 := curve.AddUnified(&c.M, rPubkey)
	curve.AssertIsEqual(&c.C2, expectedC2)
	return nil
}

type ElGamalCircuit struct {
	C1     sw_bn254.G1Affine `gnark:",public"`	//ElGamal 密文 C1 = r*G
	C2     sw_bn254.G1Affine `gnark:",public"` 	//ElGamal 密文 C2 = M + r*Pubkey
	Pubkey sw_bn254.G1Affine `gnark:",public"`	//ElGamal 公钥 Pubkey = s*G

	R sw_bn254.Scalar    //ElGamal 随机数 r
	M sw_bn254.G1Affine  //ElGamal 明文 M
}

// ElGamal 加密电路逻辑定义
func (c *ElGamalCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}

	curve.AssertIsOnCurve(&c.C1)
	curve.AssertIsOnCurve(&c.C2)
	curve.AssertIsOnCurve(&c.Pubkey)
	curve.AssertIsOnCurve(&c.M)

	rG := curve.ScalarMulBase(&c.R)
	curve.AssertIsEqual(&c.C1, rG)

	rPubkey := curve.ScalarMul(&c.Pubkey, &c.R)
	expectedC2 := curve.AddUnified(&c.M, rPubkey)
	curve.AssertIsEqual(&c.C2, expectedC2)

	return nil
}

func Groth16() {
	// 创建一个 CTRMiMC 实例
	var myCircuit CTRMiMCCircuit

	// 编译电路，生成 R1CS
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 设置证明密钥 pk 和验证密钥 vk
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 创建一个有效的电路实例
	validCircuit := &CTRMiMCCircuit{
		Plaintext:  [MAX_N]frontend.Variable{1, 2, 3, 4, 5},
		Ciphertext: [MAX_N]frontend.Variable{1, 2, 3, 4, 6},
		Key:        19,
		Nonce:      9,
	}

	// 创建 witness
	witness, err := frontend.NewWitness(validCircuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		return
	}

	// 生成证明
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 创建公共见证
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println(err)
		return
	}

	// 验证证明
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		return
	} else {
		// 验证成功
		fmt.Printf("Verify sucess ! \n")
	}
}
