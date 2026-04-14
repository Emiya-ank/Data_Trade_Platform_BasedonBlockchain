package offchain

import (
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	gchash "github.com/consensys/gnark-crypto/hash"

	// 导入Poseidon2哈希函数包以注册它们
	_ "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	_ "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	_ "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/poseidon2"
	_ "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/poseidon2"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	_ "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/poseidon2"
	_ "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/poseidon2"
)

type Poseidon2Case struct {
	Curve ecc.ID
	Hash  hash.Hash
}

var Poseidon2CaseMap = map[string]Poseidon2Case{
	"BN254":     {ecc.BN254, gchash.POSEIDON2_BN254.New()},
	"BLS12-377": {ecc.BLS12_377, gchash.POSEIDON2_BLS12_377.New()},
	"BLS12-381": {ecc.BLS12_381, gchash.POSEIDON2_BLS12_381.New()},
	"BLS24-315": {ecc.BLS24_315, gchash.POSEIDON2_BLS24_315.New()},
	"BLS24-317": {ecc.BLS24_317, gchash.POSEIDON2_BLS24_317.New()},
	"BW6-633":   {ecc.BW6_633, gchash.POSEIDON2_BW6_633.New()},
	"BW6-761":   {ecc.BW6_761, gchash.POSEIDON2_BW6_761.New()},
}

func Poseidon2Hash(h hash.Hash, data *big.Int) []byte {
	h.Reset()
	h.Write(data.Bytes())
	return h.Sum(nil)
}
