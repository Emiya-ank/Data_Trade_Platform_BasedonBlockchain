package offchain

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"

	"github.com/consensys/gnark/constraint"
)

func GenerateKZG_SRS(ccs constraint.ConstraintSystem, maxSize int) (*kzg.SRS, *kzg.SRS, error) {
	srs, err := kzg.NewSRS(uint64(maxSize), ecc.BN254.ScalarField())
	return srs, nil, err
}

// 序列化 SRS 到文件
func ExportSRS(srs *kzg.SRS, path string) error {
	file, err := os.Create(path)
	if err != nil {
		panic("SRS 序列化文件创建失败！")
	}
	defer file.Close()

	_, err = srs.WriteTo(file)
	if err != nil {
		panic("SRS 序列化文件写入失败！")
	}

	return  err
}

// 从文件反序列化 SRS
func ImportSRS(path string) (*kzg.SRS, error) {
	file, err := os.Open(path)
	if err != nil {
		panic("SRS 反序列化文件打开失败！")
	}
	defer file.Close()

	var srs kzg.SRS
	_, err = srs.ReadFrom(file)
	if err != nil {
		panic("SRS 反序列化文件读取失败！")
	}

	return &srs, err
}