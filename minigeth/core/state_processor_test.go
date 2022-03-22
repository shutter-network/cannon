package core

import (
	"bytes"
	"crypto/ecdsa"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/oracle"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const nodeUrl = "http://localhost:8545"

var (
	config             = params.TestChainConfig
	genesisHash        = common.HexToHash("0xd702d0441aa0045ac875b526e6ea7064e67604ef2162034a9b7260540f3e9f25")
	sequencerKey       *ecdsa.PrivateKey
	sequencerAddress   common.Address
	userKey            *ecdsa.PrivateKey
	userAddress        common.Address
	contractDeployData = common.Hex2Bytes("608060405234801561001057600080fd5b5061012f806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806367e0badb146037578063cd16ecbf146051575b600080fd5b603d6069565b6040516048919060c2565b60405180910390f35b6067600480360381019060639190608f565b6072565b005b60008054905090565b8060008190555050565b60008135905060898160e5565b92915050565b60006020828403121560a057600080fd5b600060ac84828501607c565b91505092915050565b60bc8160db565b82525050565b600060208201905060d5600083018460b5565b92915050565b6000819050919050565b60ec8160db565b811460f657600080fd5b5056fea2646970667358221220f8b1948f74d297fafd90786c1af95e17b6a57ed35fbb91db4ccbaaf5711c59c864736f6c63430008040033")
	contractCallData   = common.Hex2Bytes("cd16ecbf0000000000000000000000000000000000000000000000000000000000000001")
)

func init() {
	sequencerKey, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	sequencerAddress = crypto.PubkeyToAddress(sequencerKey.PublicKey)
	userKey, _ = crypto.HexToECDSA("b0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773")
	userAddress = crypto.PubkeyToAddress(userKey.PublicKey)

	oracle.SetNodeUrl(nodeUrl)
}

func prepare(t *testing.T) (types.Header, *state.StateDB) {
	t.Helper()

	oracle.PrefetchBlock(new(big.Int).SetUint64(0), true, nil)
	parent := types.Header{}
	err := rlp.DecodeBytes(oracle.Preimage(genesisHash), &parent)
	if err != nil {
		t.Fatal(err)
	}

	database := state.NewDatabase(parent)
	statedb, err := state.New(parent.Root, database, nil)
	if err != nil {
		t.Fatal(err)
	}

	return parent, statedb
}

func process(t *testing.T, parent types.Header, statedb *state.StateDB, transactions []*types.Transaction) (types.Receipts, []*types.Log, uint64, error) {
	t.Helper()

	vmconfig := vm.Config{NoBaseFee: true}
	bc := NewBlockChain(&parent)

	header := types.Header{
		ParentHash: parent.Hash(),
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      parent.Bloom,
		Difficulty: parent.Difficulty,
		Number:     new(big.Int).Add(parent.Number, big.NewInt(1)),
		GasLimit:   parent.GasLimit,
		// GasUsed     uint64
		Time:      parent.Time,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: misc.CalcBaseFee(config, &parent),
	}
	block := types.NewBlock(&header, transactions, nil, nil, trie.NewStackTrie(nil))

	processor := NewStateProcessor(config, bc, bc.Engine())
	receipts, logs, gasUsed, err := processor.Process(block, statedb, vmconfig)
	return receipts, logs, gasUsed, err
}

func TestEmptyBlock(t *testing.T) {
	parent, statedb := prepare(t)
	transactions := []*types.Transaction{}
	_, _, _, err := process(t, parent, statedb, transactions)
	t.Log(err)
	if err == nil {
		t.Fatal()
	}
}

func TestOnlyDecryptionKey(t *testing.T) {
	parent, statedb := prepare(t)
	transactions := []*types.Transaction{
		types.NewTx(&types.BatchContextTx{
			ChainID:       config.ChainID,
			DecryptionKey: []byte{},
		}),
	}
	receipts, logs, gasUsed, err := process(t, parent, statedb, transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatal("expected 0 receipts")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed > 0 {
		t.Fatal("expected 0 gas used")
	}
}

func TestEmptyShutterTx(t *testing.T) {
	parent, statedb := prepare(t)
	contextTx := &types.BatchContextTx{
		ChainID:       config.ChainID,
		DecryptionKey: []byte{},
	}
	shutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              0,
		EncryptedPayload: []byte{},
	}
	signer := types.LatestSigner(config)
	signedTx, err := types.SignNewTx(userKey, signer, shutterTx)
	if err != nil {
		t.Fatal(err)
	}
	transactions := []*types.Transaction{
		types.NewTx(contextTx),
		signedTx,
	}

	receipts, logs, gasUsed, err := process(t, parent, statedb, transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatal("expected 0 receipts")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 0 {
		t.Fatal("expected 0 gas used")
	}
}

func TestEmptyShutterTxWithFee(t *testing.T) {
	parent, statedb := prepare(t)
	contextTx := &types.BatchContextTx{
		ChainID:       config.ChainID,
		DecryptionKey: []byte{},
	}
	shutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(500), // much smaller than base fee
		Gas:              100,
		EncryptedPayload: []byte{},
	}
	signer := types.LatestSigner(config)
	signedTx, err := types.SignNewTx(userKey, signer, shutterTx)
	if err != nil {
		t.Fatal(err)
	}
	transactions := []*types.Transaction{
		types.NewTx(contextTx),
		signedTx,
	}
	userBalancePre := statedb.GetBalance(userAddress)

	receipts, logs, gasUsed, err := process(t, parent, statedb, transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatal("expected 0 receipts")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 0 {
		t.Fatal("expected 0 gas used")
	}

	userBalancePost := statedb.GetBalance(userAddress)
	userBalanceDiff := new(big.Int).Sub(userBalancePost, userBalancePre)

	expectedFee := new(big.Int).Mul(shutterTx.GasFeeCap, new(big.Int).SetUint64(shutterTx.Gas))
	if new(big.Int).Neg(userBalanceDiff).Cmp(expectedFee) != 0 {
		t.Fatalf("expected user balance to increase by %d, got %d", expectedFee, new(big.Int).Neg(userBalanceDiff))
	}
}

func TestTransfer(t *testing.T) {
	parent, statedb := prepare(t)
	contextTx := &types.BatchContextTx{
		ChainID:       config.ChainID,
		DecryptionKey: []byte{},
	}

	receiver := common.HexToAddress("2222222222222222222222222222222222222222")
	amount := big.NewInt(100)
	decryptedPayload := types.DecryptedPayload{
		To:    &receiver,
		Value: amount,
		Data:  []byte{},
	}
	decryptedPayloadEncoded, err := rlp.EncodeToBytes(decryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	shutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              21000,
		EncryptedPayload: decryptedPayloadEncoded, // TODO: encrypt
	}
	signer := types.LatestSigner(config)
	signedTx, err := types.SignNewTx(userKey, signer, shutterTx)
	if err != nil {
		t.Fatal(err)
	}
	transactions := []*types.Transaction{
		types.NewTx(contextTx),
		signedTx,
	}

	senderBalancePre := statedb.GetBalance(userAddress)
	receiverBalancePre := statedb.GetBalance(receiver)

	receipts, logs, gasUsed, err := process(t, parent, statedb, transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatal("expected 1 receipt")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("tx should have been successful")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 21000 {
		t.Fatalf("expected 21000 gas used, got %d", gasUsed)
	}

	senderBalancePost := statedb.GetBalance(userAddress)
	receiverBalancePost := statedb.GetBalance(receiver)

	senderBalanceDiff := new(big.Int).Sub(senderBalancePost, senderBalancePre)
	receiverBalanceDiff := new(big.Int).Sub(receiverBalancePost, receiverBalancePre)

	if senderBalanceDiff.Cmp(new(big.Int).Neg(amount)) != 0 {
		t.Fatalf("expected sender balance to decrease by %d, got increase by %d", amount, senderBalanceDiff)
	}
	if receiverBalanceDiff.Cmp(amount) != 0 {
		t.Fatalf("expected receiver balance to increase by %d, got %d", amount, receiverBalanceDiff)
	}
}

func TestContractCall(t *testing.T) {
	parent, statedb := prepare(t)
	contextTx := &types.BatchContextTx{
		ChainID:       config.ChainID,
		DecryptionKey: []byte{},
	}

	decryptedDeployPayload := types.DecryptedPayload{
		To:    nil,
		Value: big.NewInt(0),
		Data:  contractDeployData,
	}
	decryptedDeployPayloadEncoded, err := rlp.EncodeToBytes(decryptedDeployPayload)
	if err != nil {
		t.Fatal(err)
	}
	deployTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              1000000,
		EncryptedPayload: decryptedDeployPayloadEncoded, // TODO: encrypt
	}

	contractAddress := common.HexToAddress("0xFA33c8EF8b5c4f3003361c876a298D1DB61ccA4e")
	decryptedCallPayload := types.DecryptedPayload{
		To:    &contractAddress,
		Value: big.NewInt(0),
		Data:  contractCallData,
	}
	decryptedCallPayloadEncoded, err := rlp.EncodeToBytes(decryptedCallPayload)
	if err != nil {
		t.Fatal(err)
	}
	callTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            1,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              100000,
		EncryptedPayload: decryptedCallPayloadEncoded, // TODO: encrypt
	}

	signer := types.LatestSigner(config)
	signedDeployTx, err := types.SignNewTx(userKey, signer, deployTx)
	if err != nil {
		t.Fatal(err)
	}
	signedCallTx, err := types.SignNewTx(userKey, signer, callTx)
	if err != nil {
		t.Fatal(err)
	}
	transactions := []*types.Transaction{
		types.NewTx(contextTx),
		signedDeployTx,
		signedCallTx,
	}

	receipts, logs, _, err := process(t, parent, statedb, transactions)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("receipts", receipts)
	if len(receipts) != 2 {
		t.Fatal("expected 2 receipts")
	}
	if receipts[1].Status != types.ReceiptStatusSuccessful {
		t.Fatal("tx should have been successful")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
}

func TestContractDeployment(t *testing.T) {
	parent, statedb := prepare(t)
	contextTx := &types.BatchContextTx{
		ChainID:       config.ChainID,
		DecryptionKey: []byte{},
	}

	decryptedPayload := types.DecryptedPayload{
		To:    nil,
		Value: big.NewInt(0),
		Data:  contractDeployData,
	}
	decryptedPayloadEncoded, err := rlp.EncodeToBytes(decryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	shutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        big.NewInt(0),
		Gas:              1000000,
		EncryptedPayload: decryptedPayloadEncoded, // TODO: encrypt
	}
	signer := types.LatestSigner(config)
	signedTx, err := types.SignNewTx(userKey, signer, shutterTx)
	if err != nil {
		t.Fatal(err)
	}
	transactions := []*types.Transaction{
		types.NewTx(contextTx),
		signedTx,
	}

	receipts, logs, _, err := process(t, parent, statedb, transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatal("expected 1 receipts")
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatal("tx should have been successful")
	}
	if bytes.Equal(receipts[0].ContractAddress.Bytes(), common.Address{}.Bytes()) {
		t.Fatal("should have deployed contract")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}

	// code := statedb.GetCode(receipts[0].ContractAddress)
	// if len(code) == 0 {
	// 	t.Fatal("should have deployed contract")
	// }
}
