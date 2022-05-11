package core

import (
	"bytes"
	_ "embed"
	"encoding/json"

	"github.com/ethereum/go-ethereum/abi"
)

var (
	eonKeyStorageABI  abi.ABI
	eonKeyStorageJSON map[string]interface{}

	addrsSeqABI  abi.ABI
	addrsSeqJSON map[string]interface{}

	collatorConfigABI  abi.ABI
	collatorConfigJSON map[string]interface{}

	batchCounterABI  abi.ABI
	batchCounterJSON map[string]interface{}
)

//go:embed EonKeyStorage.json
var eonKeyStorageRaw []byte

//go:embed AddrsSeq.json
var addrsSeqRaw []byte

//go:embed CollatorConfigsList.json
var collatorConfigRaw []byte

//go:embed BatchCounter.json
var batchCounterRaw []byte

type activeConfigReturnValue struct {
	ActivationBlockNumber uint64 "json:\"activationBlockNumber\""
	SetIndex              uint64 "json:\"setIndex\""
}

func init() {
	var err error

	err = json.Unmarshal(eonKeyStorageRaw, &eonKeyStorageJSON)
	if err != nil {
		panic(err)
	}
	eonKeyStorageABIRaw, err := json.Marshal(eonKeyStorageJSON["abi"])
	if err != nil {
		panic(err)
	}
	eonKeyStorageABI, err = abi.JSON(bytes.NewReader(eonKeyStorageABIRaw))
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(addrsSeqRaw, &addrsSeqJSON)
	if err != nil {
		panic(err)
	}
	addrsSeqABIRaw, err := json.Marshal(addrsSeqJSON["abi"])
	if err != nil {
		panic(err)
	}
	addrsSeqABI, err = abi.JSON(bytes.NewReader(addrsSeqABIRaw))
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(collatorConfigRaw, &collatorConfigJSON)
	if err != nil {
		panic(err)
	}
	collatorConfigABIRaw, err := json.Marshal(collatorConfigJSON["abi"])
	if err != nil {
		panic(err)
	}
	collatorConfigABI, err = abi.JSON(bytes.NewReader(collatorConfigABIRaw))
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(batchCounterRaw, &batchCounterJSON)
	if err != nil {
		panic(err)
	}
	batchCounterABIRaw, err := json.Marshal(batchCounterJSON["abi"])
	if err != nil {
		panic(err)
	}
	batchCounterABI, err = abi.JSON(bytes.NewReader(batchCounterABIRaw))
	if err != nil {
		panic(err)
	}
}
