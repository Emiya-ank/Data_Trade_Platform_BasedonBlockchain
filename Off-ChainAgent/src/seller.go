package offchain

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"golang.org/x/crypto/sha3"
)

var (
	pedersenGeneratorsOnce sync.Once
	pedersenGenerators     []*big.Int
)

// 读取明文
func ReadPlaintext(path string, maxLen int) ([]*big.Int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	if len(data) > maxLen {
		data = data[:maxLen]
	}

	plaintext := make([]*big.Int, maxLen)
	for i := 0; i < maxLen; i++ {
		if i < len(data) {
			plaintext[i] = big.NewInt(int64(data[i])) // byte → field element
		} else {
			plaintext[i] = big.NewInt(0) // padding
		}
	}
	return plaintext, len(data), nil
}

// 生成轮常量（使用 Keccak256 生成伪随机常数）
func RoundConstantGeneration() []*big.Int {
	rc := make([]*big.Int, ROUNDS)

	var seed [32]byte
	seed = sha3.Sum256(seed[:]) // c_0 = Keccak256(0)

	// BN254 标量域的素数
	p := fr.Modulus()

	for i := 0; i < ROUNDS; i++ {
		// c_i = Keccak256(c_{i-1}) mod p
		seed = sha3.Sum256(seed[:])
		// 将哈希结果转换为大整数
		hashValue := new(big.Int).SetBytes(seed[:])
		// 模以 BN254 标量域素数
		rc[i] = new(big.Int).Mod(hashValue, p)
	}

	return rc
}

// 生成密钥流
func MimcFunction(x *big.Int, key *big.Int, rc []*big.Int) *big.Int {
	var state fr.Element //运算定义是在大素数有限域上的
	state.SetBigInt(x)

	var k fr.Element //同上
	k.SetBigInt(key)

	// 轮函数实现
	for i := 0; i < ROUNDS; i++ {
		var c fr.Element
		c.SetBigInt(rc[i])

		// state = x_j + k + c_j
		state.Add(&state, &k)
		state.Add(&state, &c)

		// state = state^5
		var t fr.Element
		t.Square(&state)      //state^2
		t.Square(&t)          //state^4
		state.Mul(&t, &state) //state^5
	}

	output := new(big.Int)
	state.BigInt(output)

	return output
}

func KeystreamGeneration(key *big.Int, nonce *big.Int, length int) []*big.Int {
	rc := RoundConstantGeneration()
	keystream := make([]*big.Int, length)

	for i := 0; i < length; i++ {
		// ctr_i = nonce + i (mod p)
		ctr := new(big.Int).Add(nonce, big.NewInt(int64(i)))
		ctr.Mod(ctr, fr.Modulus())

		// keystream_i = MiMC(ctr_i)
		keystream[i] = MimcFunction(ctr, key, rc)
	}

	return keystream
}

// CTR模式下的MiMC加密
func MimcEncryption(plaintext []*big.Int, key *big.Int, nonce *big.Int, textLen int) []*big.Int {
	keystream := KeystreamGeneration(key, nonce, len(plaintext))
	ciphertext := make([]*big.Int, len(plaintext))

	for i := 0; i < len(plaintext); i++ {

		if i < textLen { // only encrypt valid region
			c := new(big.Int).Add(plaintext[i], keystream[i])
			c.Mod(c, fr.Modulus())
			ciphertext[i] = c
		} else {
			ciphertext[i] = big.NewInt(0) // padding region must be 0
		}
	}

	return ciphertext
}

// 将密文写为定长二进制文件
func WriteText(path string, ciphertext []*big.Int) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, c := range ciphertext {
		var e fr.Element
		e.SetBigInt(c)

		bytes := e.Bytes()
		_, err := file.Write(bytes[:])
		if err != nil {
			return err
		}
	}

	return err
}

// 定义公共输入结构
type PublicInputs struct {
	Ciphertext [MAX_N]string `json:"ciphertext"`
	Selector   [MAX_N]string `json:"selector"`
	TextLen    int           `json:"textLen"`
	Commitment *big.Int      `json:"commitment"`
}

// 导出公共见证 public.json
func ExportPublicJSON(ciphertext []*big.Int, selector []*big.Int, textlen int, commitment *big.Int, path string) error {
	if len(ciphertext) != MAX_N {
		return fmt.Errorf("ciphertext length must be %d, while got %d", MAX_N, len(ciphertext))
	}

	var pi PublicInputs
	for i := 0; i < MAX_N; i++ {
		pi.Ciphertext[i] = ciphertext[i].String()
		pi.Selector[i] = selector[i].String()
	}
	pi.TextLen = textlen
	pi.Commitment = commitment

	jsonBytes, err := json.MarshalIndent(pi, "", "  ")
	if err != nil {
		return nil
	}

	return os.WriteFile(path, jsonBytes, 0644)
}

// 导出验证密钥 vk.bin
func ExportVerifyingKey(vk groth16.VerifyingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = vk.WriteTo(file)
	return err
}

// 导出证明密钥 pk.bin
func ExportProvingKey(pk groth16.ProvingKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = pk.WriteTo(file)
	return err
}

// 导出证明 proof.bin
func ExportProof(proof groth16.Proof, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = proof.WriteTo(file)
	return err
}

// 导出见证 witness.json
func ExportWitnessJSON(w *CTRMiMCCircuit, path string) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// 生成随机数
func GenerateRandomFr() (*big.Int, error) {
	modulus := fr.Modulus()
	return rand.Int(rand.Reader, modulus)
}

// Pedersen 承诺生成元设置
func PedersenGeneratorSet() []*big.Int {
	pedersenGeneratorsOnce.Do(func() {
		pedersenGenerators = make([]*big.Int, MAX_N+1)

		var seed [32]byte
		seed = sha3.Sum256([]byte("pedersen-generators"))
		modulus := fr.Modulus()

		for i := 0; i < MAX_N+1; i++ {
			seed = sha3.Sum256(seed[:])
			pedersenGenerators[i] = new(big.Int).Mod(new(big.Int).SetBytes(seed[:]), modulus)
			if pedersenGenerators[i].Sign() == 0 {
				pedersenGenerators[i] = big.NewInt(1)
			}
		}
	})

	return pedersenGenerators
}

// 计算明文 Pedersen 承诺
func PedersenCommitment(plaintext []*big.Int, random *big.Int, textLen int) *big.Int {
	generators := PedersenGeneratorSet()
	modulus := fr.Modulus()

	C := big.NewInt(0)
	// 计算承诺 C = sum(plaintext[i] * generators[i]) + random * H，其中 H 是一个额外的生成元
	for i := 0; i < MAX_N; i++ {
		term := new(big.Int).Mul(plaintext[i], generators[i])
		C.Add(C, term)
		C.Mod(C, modulus)
	}

	H := generators[MAX_N]
	RTerm := new(big.Int).Mul(random, H)
	C.Add(C, RTerm)
	C.Mod(C, modulus)

	return C
}

// 将 G1Affine 点 M 映射到 fr 域元素（Poseidon2 哈希）
func PointToFrPoseidon(M *bn254.G1Affine) (*big.Int, error) {
	if M == nil {
		return nil, fmt.Errorf("point is nil")
	}

	if M.IsInfinity() {
		// 无穷远点映射为 0
		return big.NewInt(0), nil
	}

	// 选择 RawBytes 将 x|y 展开为 64 字节
	raw := M.RawBytes()
	mInt := new(big.Int).SetBytes(raw[:])

	poseidon2 := Poseidon2CaseMap["BN254"].Hash
	poseidon2.Reset()
	hashed := Poseidon2Hash(poseidon2, mInt)
	out := new(big.Int).SetBytes(hashed)
	out.Mod(out, fr.Modulus())

	return out, nil
}

// ElGamal 密码（椭圆曲线版本）
// ElGamal 公钥结构
type ElGamalPublicKey struct {
	Y *bn254.G1Affine // 公钥 Y = x * G
}

// ElGamal 私钥结构
type ElGamalPrivateKey *big.Int

// 生成 ElGamal 密钥对
func GenerateElGamalKey() (ElGamalPrivateKey, ElGamalPublicKey) {
	// 生成随机私钥 x
	x, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		panic(err)
	}

	// 获取G1生成元
	_, _, g1Gen, _ := bn254.Generators()

	// 公钥 Y = x * G
	var Y bn254.G1Affine
	Y.ScalarMultiplication(&g1Gen, x)

	return ElGamalPrivateKey(x), ElGamalPublicKey{Y: &Y}
}

// 生成随机点 M 和对应的随机数 r，使得 M = r * G
func RandomPoint() (bn254.G1Affine, *big.Int) {
	r, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		panic(err)
	}

	_, _, G, _ := bn254.Generators()

	var M bn254.G1Affine
	M.ScalarMultiplication(&G, r)

	return M, r
}

// ElGamal 加密函数
// 输入：消息 msg（*bn254.G1Affine），公钥 pub
// 输出：密文对 (C1, C2) 均为 *bn254.G1Affine
func ElGamalEncrypt(msg *bn254.G1Affine, pub ElGamalPublicKey) (*bn254.G1Affine, *bn254.G1Affine) {
	// 选择随机数 k
	k, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		panic(err)
	}

	// 获取G1生成元
	_, _, g1Gen, _ := bn254.Generators()

	// C1 = k * G
	var C1 bn254.G1Affine
	C1.ScalarMultiplication(&g1Gen, k)

	// k * Y
	var kY bn254.G1Affine
	kY.ScalarMultiplication(pub.Y, k)

	// C2 = msg + k * Y
	var C2 bn254.G1Affine
	C2.Add(msg, &kY)

	return &C1, &C2
}

// ElGamal 解密函数
// 输入：密文 (C1, C2)，私钥 priv
// 输出：解密后的消息 *bn254.G1Affine
func ElGamalDecrypt(C1, C2 *bn254.G1Affine, priv ElGamalPrivateKey) *bn254.G1Affine {
	x := (*big.Int)(priv)

	// 计算 x * C1
	var xC1 bn254.G1Affine
	xC1.ScalarMultiplication(C1, x)

	// M = C2 - x * C1
	var M bn254.G1Affine
	M.Sub(C2, &xC1)

	return &M
}
