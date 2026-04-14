package offchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// 读取公共输入JSON
func LoadPublicInputs(path string) (*PublicInputs, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pi PublicInputs
	err = json.Unmarshal(data, &pi)
	if err != nil {
		return nil, err
	}

	return &pi, nil
}

// 构造公共witness
func BuildPublicWitness(pi *PublicInputs) (frontend.Circuit, witness.Witness, error) {
	circuit := &CTRMiMCCircuit{}

	var ct [MAX_N]frontend.Variable
	for i := 0; i < MAX_N; i++ {
		ct[i] = pi.Ciphertext[i]
	}

	pub := &CTRMiMCCircuit{
		Ciphertext: ct,
		TextLen:    pi.TextLen,
	}

	w, err := frontend.NewWitness(pub, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	publicW, err := w.Public()
	if err != nil {
		return nil, nil, err
	}

	return circuit, publicW, nil
}

// 从二进制文件中读取密文
func ReadCiphertext(path string) ([]*big.Int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ciphertext := make([]*big.Int, 0, MAX_N)
	buffer := make([]byte, 32)

	for {
		_, err := io.ReadFull(file, buffer)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			return nil, err
		}
		if err != nil {
			return nil, err
		}

		var e fr.Element
		e.SetBytes(buffer)

		bi := new(big.Int)
		e.BigInt(bi)

		ciphertext = append(ciphertext, bi)
	}

	// 检查密文长度是否满足电路约束
	if len(ciphertext) != MAX_N {
		return nil, fmt.Errorf("invalid ciphertext length: got %d expected %d", len(ciphertext), MAX_N)
	}

	return ciphertext, nil
}

// MiMC密码解密
func MimcDecryption(ciphertext []*big.Int, key *big.Int, nonce *big.Int, textLen int) []*big.Int {
	keystream := KeystreamGeneration(key, nonce, len(ciphertext))

	plaintext := make([]*big.Int, len(ciphertext))

	for i := 0; i < len(ciphertext); i++ {
		if i < textLen { // only encrypt valid region
			c := new(big.Int).Sub(ciphertext[i], keystream[i])
			c.Mod(c, fr.Modulus())
			plaintext[i] = c
		} else {
			plaintext[i] = big.NewInt(0) // padding region must be 0
		}
	}

	return plaintext
}

// 加载密钥哈希 keyHash.json
func LoadKeyHash(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var kh KH
	if err := json.Unmarshal(data, &kh); err != nil {
		return nil, err
	}

	return hex.DecodeString(kh.KeyHash)
}

func Verify(vkPath string, proofPath string, publicInputPath string) error {

	// 1. 加载 vk
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return fmt.Errorf("failed to open verifying key: %w", err)
	}

	// 检查文件大小
	stat, err := vkFile.Stat()
	if err != nil {
		vkFile.Close()
		return fmt.Errorf("failed to stat vk file: %w", err)
	}
	if stat.Size() == 0 {
		vkFile.Close()
		return fmt.Errorf("verifying key file is empty: %s", vkPath)
	}

	var vk groth16.VerifyingKey
	n, err := vk.ReadFrom(vkFile)
	vkFile.Close()

	if err != nil {
		return fmt.Errorf("failed to read verifying key: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("read 0 bytes from verifying key file, file might be corrupted or empty")
	}

	// 2. 加载 proof
	proofFile, err := os.Open(proofPath)
	if err != nil {
		return fmt.Errorf("failed to open proof: %w", err)
	}

	stat, err = proofFile.Stat()
	if err != nil {
		proofFile.Close()
		return fmt.Errorf("failed to stat proof file: %w", err)
	}
	if stat.Size() == 0 {
		proofFile.Close()
		return fmt.Errorf("proof file is empty: %s", proofPath)
	}

	var proof groth16.Proof
	n, err = proof.ReadFrom(proofFile)
	proofFile.Close()

	if err != nil {
		return fmt.Errorf("failed to read proof: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("read 0 bytes from proof file, file might be corrupted or empty")
	}

	// 3. 加载 public inputs
	publicInputs, err := LoadPublicInputs(publicInputPath)
	if err != nil {
		return fmt.Errorf("failed to load public inputs: %w", err)
	}

	// 4. 构造 public witness
	assignment, publicWitness, err := BuildPublicWitness(publicInputs)
	if err != nil {
		return fmt.Errorf("failed to build public witness: %w", err)
	}

	if publicWitness == nil {
		return fmt.Errorf("publicWitness is nil")
	}
	if assignment == nil {
		return fmt.Errorf("assignment is nil")
	}

	// 5. 验证
	if err = groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}
