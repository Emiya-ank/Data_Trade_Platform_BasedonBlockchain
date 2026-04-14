package main

import (
	"log"

	smartcontract "chaincode/src"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	cc, err := contractapi.NewChaincode(new(smartcontract.SmartContract))
	if err != nil {
		log.Panicf("create chaincode failed: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("start chaincode failed: %v", err)
	}
}

