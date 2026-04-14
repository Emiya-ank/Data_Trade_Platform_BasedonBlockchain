package main

import (
	offchain "Off-ChainAgent/src"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash"
	stdposeidon2 "github.com/consensys/gnark/std/permutation/poseidon2"
)

type ElGamalCircuit struct {
	C1     sw_bn254.G1Affine `gnark:",public"`
	C2     sw_bn254.G1Affine `gnark:",public"`
	Pubkey sw_bn254.G1Affine `gnark:",public"`

	R sw_bn254.Scalar
	M sw_bn254.G1Affine
}

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

type PointPoseidonCircuit struct {
	Block0    frontend.Variable
	Block1    frontend.Variable
	UseSecond frontend.Variable
	Digest    frontend.Variable `gnark:",public"`
}

func (c *PointPoseidonCircuit) Define(api frontend.API) error {
	params := poseidon2_bn254.GetDefaultParameters()
	perm, err := stdposeidon2.NewPoseidon2FromParameters(api, 2, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return err
	}

	api.AssertIsBoolean(c.UseSecond)
	poseidonHasher := hash.NewMerkleDamgardHasher(api, perm, 0)
	poseidonHasher.Write(c.Block0)
	stateAfterOne := poseidonHasher.Sum()
	poseidonHasher.Write(c.Block1)
	stateAfterTwo := poseidonHasher.Sum()
	computed := api.Select(c.UseSecond, stateAfterTwo, stateAfterOne)
	api.AssertIsEqual(computed, c.Digest)
	return nil
}

func splitToPoseidonMDBlocks(data []byte) (block0, block1 *big.Int, useSecond int) {
	const blockSize = 32

	if len(data) <= blockSize {
		padded := make([]byte, blockSize)
		copy(padded[blockSize-len(data):], data)
		return new(big.Int).SetBytes(padded), big.NewInt(0), 0
	}

	first := data[:blockSize]
	rest := data[blockSize:]
	paddedRest := make([]byte, blockSize)
	copy(paddedRest[blockSize-len(rest):], rest)
	return new(big.Int).SetBytes(first), new(big.Int).SetBytes(paddedRest), 1
}

func runElGamalCircuitProof() {
	priv, pub := offchain.GenerateElGamalKey()

	// Use G1 generator as message point.
	_, _, msg, _ := bn254.Generators()

	// Sample ElGamal randomness r and build ciphertext from the relation:
	// C1 = rG, C2 = M + rY.
	r, err := rand.Int(rand.Reader, fr_bn254.Modulus())
	if err != nil {
		panic(err)
	}

	_, _, g1Gen, _ := bn254.Generators()

	var c1 bn254.G1Affine
	c1.ScalarMultiplication(&g1Gen, r)

	var rPubkey bn254.G1Affine
	rPubkey.ScalarMultiplication(pub.Y, r)

	var c2 bn254.G1Affine
	c2.Add(&msg, &rPubkey)

	decrypted := offchain.ElGamalDecrypt(&c1, &c2, priv)
	fmt.Printf("Message:   (%s, %s)\n", msg.X.String(), msg.Y.String())
	fmt.Printf("Cipher C1: (%s, %s)\n", c1.X.String(), c1.Y.String())
	fmt.Printf("Cipher C2: (%s, %s)\n", c2.X.String(), c2.Y.String())
	fmt.Printf("Decrypt:   (%s, %s)\n", decrypted.X.String(), decrypted.Y.String())

	var rFr fr_bn254.Element
	rFr.SetBigInt(r)

	var circuit ElGamalCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	assignment := ElGamalCircuit{
		C1:     sw_bn254.NewG1Affine(c1),
		C2:     sw_bn254.NewG1Affine(c2),
		Pubkey: sw_bn254.NewG1Affine(*pub.Y),
		R:      sw_bn254.NewScalar(rFr),
		M:      sw_bn254.NewG1Affine(msg),
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}

	fmt.Println("ElGamal circuit constraints verified successfully.")
}

func runPointToFrPoseidonTestAndProof() {
	_, _, msgPoint, _ := bn254.Generators()

	got, err := offchain.PointToFrPoseidon(&msgPoint)
	if err != nil {
		panic(err)
	}

	gotAgain, err := offchain.PointToFrPoseidon(&msgPoint)
	if err != nil {
		panic(err)
	}
	if got.Cmp(gotAgain) != 0 {
		panic("PointToFrPoseidon is not deterministic for same input point")
	}

	if _, err := offchain.PointToFrPoseidon(nil); err == nil {
		panic("PointToFrPoseidon(nil) should return an error")
	}

	var infinity bn254.G1Affine
	infOut, err := offchain.PointToFrPoseidon(&infinity)
	if err != nil {
		panic(err)
	}
	if infOut.Cmp(big.NewInt(0)) != 0 {
		panic("PointToFrPoseidon(infinity) should return 0")
	}

	raw := msgPoint.RawBytes()
	pointInt := new(big.Int).SetBytes(raw[:])
	block0, block1, useSecond := splitToPoseidonMDBlocks(pointInt.Bytes())

	var circuit PointPoseidonCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	assignment := PointPoseidonCircuit{
		Block0:    block0,
		Block1:    block1,
		UseSecond: useSecond,
		Digest:    got,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		panic(err)
	}

	fmt.Printf("PointToFrPoseidon output: %s\n", got.String())
	fmt.Println("PointToFrPoseidon function checks and circuit proof verified successfully.")
}

// func main() {
// 	runElGamalCircuitProof()
// 	runPointToFrPoseidonTestAndProof()
// }
