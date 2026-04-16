package main

import (
	offchain "Off-ChainAgent/src"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test/unsafekzg"
)

// proofSizeBytes 计算证明对象的字节大小，要求证明对象实现 WriteTo(io.Writer) 方法。
func proofSizeBytes(proof interface{}) (int64, error) {
	writerTo, ok := proof.(interface {
		WriteTo(io.Writer) (int64, error)
	})
	if !ok {
		return 0, fmt.Errorf("proof does not implement WriteTo(io.Writer)")
	}

	var buf bytes.Buffer
	n, err := writerTo.WriteTo(&buf)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return n, nil
	}
	return int64(buf.Len()), nil
}

// mustEnv 获取环境变量值，如果未设置则返回错误。
func mustEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("missing environment variable: %s", key)
	}
	return v, nil
}

// envInt64 获取环境变量并解析为 int64，如果未设置则返回默认值。
func envInt64(key string, defaultValue int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid int64 for %s: %w", key, err)
	}
	return n, nil
}

//runFabricTradeFlow 演示完整的 Fabric 交易流程：CreateTrade -> LockTrade -> SubmitKeyandVerify。
//每个步骤都会查询交易状态并打印，最后验证交易成功完成。
func runFabricTradeFlow(key *big.Int, keyHashBytes []byte) error {
	if os.Getenv("FABRIC_ENABLE") != "1" {
		fmt.Println("14. Skip on-chain flow (set FABRIC_ENABLE=1 to enable)")
		return nil
	}

	mspID, err := mustEnv("FABRIC_MSP_ID")
	if err != nil {
		return err
	}
	peerEndpoint, err := mustEnv("FABRIC_PEER_ENDPOINT")
	if err != nil {
		return err
	}
	gatewayPeer, err := mustEnv("FABRIC_GATEWAY_PEER")
	if err != nil {
		return err
	}
	tlsCertPath, err := mustEnv("FABRIC_TLS_CERT")
	if err != nil {
		return err
	}
	certPath, err := mustEnv("FABRIC_CERT_PATH")
	if err != nil {
		return err
	}
	keyPath, err := mustEnv("FABRIC_KEY_PATH")
	if err != nil {
		return err
	}
	channelName, err := mustEnv("FABRIC_CHANNEL")
	if err != nil {
		return err
	}
	chaincodeName, err := mustEnv("FABRIC_CHAINCODE")
	if err != nil {
		return err
	}
	sellerClientID, err := mustEnv("FABRIC_SELLER_CLIENT_ID")
	if err != nil {
		return err
	}

	amount, err := envInt64("FABRIC_TRADE_AMOUNT", 100)
	if err != nil {
		return err
	}
	initBalanceAmount, err := envInt64("FABRIC_INIT_BALANCE", 1000)
	if err != nil {
		return err
	}
	timeoutSeconds, err := envInt64("FABRIC_TRADE_TIMEOUT_SECONDS", 3600)
	if err != nil {
		return err
	}

	tradeID := os.Getenv("FABRIC_TRADE_ID")
	if tradeID == "" {
		tradeID = fmt.Sprintf("trade-%d", time.Now().Unix())
	}

	cfg := offchain.FabricConfig{
		MSPID:         mspID,
		PeerEndpoint:  peerEndpoint,
		GatewayPeer:   gatewayPeer,
		TLSCertPath:   tlsCertPath,
		CertPath:      certPath,
		KeyPath:       keyPath,
		ChannelName:   channelName,
		ChaincodeName: chaincodeName,
	}

	fabricClient, err := offchain.NewFabricClient(cfg)
	if err != nil {
		return fmt.Errorf("NewFabricClient failed: %w", err)
	}
	defer fabricClient.Close()

	keyHashHex := hex.EncodeToString(keyHashBytes)

	fmt.Printf("14.0 InitBalance: amount=%d\n", initBalanceAmount)
	if err := fabricClient.InitBalance(initBalanceAmount); err != nil {
		return fmt.Errorf("InitBalance failed: %w", err)
	}

	fmt.Printf("14.1 CreateTrade: id=%s timeout=%d\n", tradeID, timeoutSeconds)
	if err := fabricClient.CreateTrade(tradeID, sellerClientID, timeoutSeconds, keyHashHex); err != nil {
		return fmt.Errorf("CreateTrade failed: %w", err)
	}

	fmt.Printf("14.2 LockTrade: id=%s amount=%d\n", tradeID, amount)
	if err := fabricClient.LockTrade(tradeID, amount); err != nil {
		return fmt.Errorf("LockTrade failed: %w", err)
	}

	lockedTrade, err := fabricClient.GetTrade(tradeID)
	if err != nil {
		return fmt.Errorf("GetTrade after lock failed: %w", err)
	}
	fmt.Printf("14.3 Status after lock: %s\n", lockedTrade.Status)
	if lockedTrade.Status != "LOCKED" {
		return fmt.Errorf("unexpected status after lock: %s", lockedTrade.Status)
	}

	fmt.Printf("14.4 SubmitKeyandVerify: id=%s key=%s\n", tradeID, key.String())
	if err := fabricClient.SubmitKeyAndVerify(tradeID, key.String()); err != nil {
		return fmt.Errorf("SubmitKeyandVerify failed: %w", err)
	}

	doneTrade, err := fabricClient.GetTrade(tradeID)
	if err != nil {
		return fmt.Errorf("GetTrade after submit failed: %w", err)
	}
	fmt.Printf("14.5 Final status: %s\n", doneTrade.Status)
	if doneTrade.Status != "DONE" {
		return fmt.Errorf("unexpected final status: %s", doneTrade.Status)
	}

	fmt.Println("On-chain flow passed: CreateTrade -> LockTrade -> SubmitKeyandVerify")
	return nil
}

func main() {
	fmt.Println("Start tradeflow test")

	testpath := "./data/data.txt"
	testpath2 := "./data/encrypted_data.bin"
	publicInputspath := "./data/publicInputs.json"
	pkpath := "./data/pk.bin"
	vkpath := "./data/vk.bin"
	proofpath := "./data/proof.bin"
	witnesspath := "./data/witness.json"

	fmt.Println("1. 读取明文")
	plaintext, textLen, err := offchain.ReadPlaintext(testpath, offchain.MAX_N)
	if err != nil {
		panic(fmt.Sprintf("ReadPlaintext failed: %v", err))
	}
	fmt.Printf("读取成功, textLen=%d\n!", textLen)

	fmt.Println("2. 生成 MiMC 轮常量")
	rc := offchain.RoundConstantGeneration()
	if len(rc) != offchain.ROUNDS {
		panic(fmt.Sprintf("round constants size mismatch: got=%d want=%d", len(rc), offchain.ROUNDS))
	}
	fmt.Printf("轮常量生成成功! 共 %d 个轮常量\n", len(rc))

	fmt.Println("3. 密钥流生成")
	M, r := offchain.RandomPoint()
	key, err := offchain.PointToFrPoseidon(&M)
	if err != nil {
		panic(fmt.Sprintf("PointToFrPoseidon failed: %v", err))
	}
	fmt.Printf("随机生成的密钥: %s\n", key.String())
	nonce := big.NewInt(9)
	keystream := offchain.KeystreamGeneration(key, nonce, len(plaintext))
	if len(keystream) != len(plaintext) {
		panic(fmt.Sprintf("keystream length mismatch: got=%d want=%d", len(keystream), len(plaintext)))
	}
	fmt.Printf("密钥流生成成功! keystream length=%d\n", len(keystream))

	fmt.Println("4. CTR 模式下的 MiMC 加密")
	ciphertext := offchain.MimcEncryption(plaintext, key, nonce, textLen)
	if len(ciphertext) != len(plaintext) {
		panic(fmt.Sprintf("ciphertext length mismatch: got=%d want=%d", len(ciphertext), len(plaintext)))
	}
	fmt.Printf("加密成功! ciphertext length=%d\n", len(ciphertext))

	fmt.Println("5. MiMC 解密")
	decryptedtext := offchain.MimcDecryption(ciphertext, key, nonce, textLen)
	for i := 0; i < len(plaintext); i++ {
		expected := new(big.Int).Mod(plaintext[i], fr.Modulus())
		actual := new(big.Int).Mod(decryptedtext[i], fr.Modulus())
		if expected.Cmp(actual) != 0 {
			panic(fmt.Sprintf("decryption mismatch at index=%d", i))
		}
	}
	fmt.Println("解密成功! 明文和解密结果一致")

	// ElGamal 加密
	_, pub := offchain.GenerateElGamalKey()
	c1, c2 := offchain.ElGamalEncrypt(&M, pub, r)

	fmt.Println("6. 导出密文")
	if err := offchain.WriteText(testpath2, ciphertext); err != nil {
		panic(fmt.Sprintf("WriteText failed: %v", err))
	}

	fmt.Println("7. 读取密文")
	ciphertext, err = offchain.ReadCiphertext(testpath2)
	if err != nil {
		panic(fmt.Sprintf("ReadCiphertext failed: %v", err))
	}
	fmt.Printf("读取成功! ciphertext length=%d\n", len(ciphertext))

	fmt.Println("8. 导出公共输入")
	selector := make([]*big.Int, offchain.MAX_N)
	for i := 0; i < offchain.MAX_N; i++ {
		if i < textLen {
			selector[i] = big.NewInt(1)
		} else {
			selector[i] = big.NewInt(0)
		}
	}
	random := big.NewInt(17)
	keyHashBytes := offchain.KeyPoseidonHash(key)
	keyHashInt := new(big.Int).SetBytes(keyHashBytes)
	keyHashInt.Mod(keyHashInt, fr.Modulus())
	commitment := offchain.PedersenCommitment(plaintext, random, textLen)
	if err := offchain.ExportPublicJSON(ciphertext, selector, textLen, keyHashInt.String(), commitment, publicInputspath); err != nil {
		panic(fmt.Sprintf("ExportPublicJSON failed: %v", err))
	}
	fmt.Println("公共输入导出成功!")

	fmt.Println("9. Groth16 电路编译")
	var myCircuit offchain.CTRMiMCCircuit
	r1csDef, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		panic(fmt.Sprintf("compile circuit failed: %v", err))
	}
	fmt.Println("Groth16 电路编译成功!")

	fmt.Println("10. Groth16协议: 导出PK/VK")
	pk, vk, err := groth16.Setup(r1csDef)
	if err != nil {
		panic(fmt.Sprintf("groth16 setup failed: %v", err))
	}
	if err := offchain.ExportVerifyingKey(vk, vkpath); err != nil {
		panic(fmt.Sprintf("export vk failed: %v", err))
	}
	fmt.Println("vk 导出成功!")
	if err := offchain.ExportProvingKey(pk, pkpath); err != nil {
		panic(fmt.Sprintf("export pk failed: %v", err))
	}
	fmt.Println("pk 导出成功!")

	fmt.Println("11. Groth16 prove")
	var w offchain.CTRMiMCCircuit
	w.Key = key
	w.KeyHash = keyHashInt
	w.Nonce = nonce
	w.TextLen = textLen
	w.Randomness = random
	w.Commitment = commitment
	var rFr fr.Element
	rFr.SetBigInt(r)
	w.C1 = sw_bn254.NewG1Affine(*c1)
	w.C2 = sw_bn254.NewG1Affine(*c2)
	w.Pubkey = sw_bn254.NewG1Affine(*pub.Y)
	w.R = sw_bn254.NewScalar(rFr)
	w.M = sw_bn254.NewG1Affine(M)

	for i := 0; i < offchain.MAX_N; i++ {
		if i < textLen {
			w.Plaintext[i] = plaintext[i]
			w.Ciphertext[i] = ciphertext[i]
			w.Selector[i] = 1
		} else {
			w.Plaintext[i] = 0
			w.Ciphertext[i] = 0
			w.Selector[i] = 0
		}
	}

	if err := offchain.ExportWitnessJSON(&w, witnesspath); err != nil {
		panic(fmt.Sprintf("ExportWitnessJSON failed: %v", err))
	}

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Sprintf("new witness failed: %v", err))
	}
	start := time.Now()
	proof, err := groth16.Prove(r1csDef, pk, witness)
	if err != nil {
		panic(fmt.Sprintf("groth16 prove failed: %v", err))
	}
	elapsed := time.Since(start)
	sizebytes, err := proofSizeBytes(proof)
	if err := offchain.ExportProof(proof, proofpath); err != nil {
		panic(fmt.Sprintf("export proof failed: %v", err))
	}
	fmt.Println("Groth16 证明生成成功!")
	fmt.Printf("Proof generation time: %s\n", elapsed)
	fmt.Printf("Groth16 Proof size: %d bytes\n", sizebytes)

	fmt.Println("12. Groth16 verify")
	publicWitness, err := witness.Public()
	if err != nil {
		panic(fmt.Sprintf("public witness failed: %v", err))
	}
	start = time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(fmt.Sprintf("groth16 verify failed: %v", err))
	}
	elapsed = time.Since(start)
	fmt.Printf("Groth16 verification time: %s\n", elapsed)
	fmt.Println("Groth16 验证成功!")

	fmt.Println("13. Plonk prove+verify")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &myCircuit)
	if err != nil {
		panic(fmt.Sprintf("plonk compile failed: %v", err))
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(fmt.Sprintf("plonk srs failed: %v", err))
	}
	pkPlonk, vkPlonk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(fmt.Sprintf("plonk setup failed: %v", err))
	}
	witnessPlonk, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic(fmt.Sprintf("plonk witness failed: %v", err))
	}
	start = time.Now()
	proofPlonk, err := plonk.Prove(ccs, pkPlonk, witnessPlonk)
	if err != nil {
		panic(fmt.Sprintf("plonk prove failed: %v", err))
	}
	elapsed = time.Since(start)
	sizebytes, err = proofSizeBytes(proofPlonk)
	fmt.Printf("Plonk proof generation time: %s\n", elapsed)
	publicWitnessPlonk, err := witnessPlonk.Public()
	if err != nil {
		panic(fmt.Sprintf("plonk public witness failed: %v", err))
	}
	start = time.Now()
	if err := plonk.Verify(proofPlonk, vkPlonk, publicWitnessPlonk); err != nil {
		panic(fmt.Sprintf("plonk verify failed: %v", err))
	}
	elapsed = time.Since(start)
	fmt.Printf("Plonk verification time: %s\n", elapsed)
	fmt.Println("Plonk 证明和验证成功!")
	fmt.Printf("Plonk Proof size: %d bytes\n", sizebytes)

	fmt.Println("14. Fabric 交易流程")

	if err := runFabricTradeFlow(key, keyHashBytes); err != nil {
		panic(err)
	}
}
