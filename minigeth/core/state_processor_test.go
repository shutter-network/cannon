// The tests require geth to run in dev mode.
// You can run geth with `SHROOT=geth_chain ../../start_geth.sh`

package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/oracle"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

const nodeUrl = "http://localhost:8545"

var (
	config                = params.TestChainConfig
	genesisHash           = common.HexToHash("0xd702d0441aa0045ac875b526e6ea7064e67604ef2162034a9b7260540f3e9f25")
	signer                types.Signer
	defaultBaseFee        = new(big.Int).SetUint64(1_000_000_000) // 1 GWei
	activationBlockNumber = big.NewInt(100)

	deployerKey      *ecdsa.PrivateKey
	deployerAddress  common.Address
	sequencerKey     *ecdsa.PrivateKey
	sequencerAddress common.Address
	userKey          *ecdsa.PrivateKey
	userAddress      common.Address

	contractDeployData = common.Hex2Bytes("608060405234801561001057600080fd5b5061012f806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806367e0badb146037578063cd16ecbf146051575b600080fd5b603d6069565b6040516048919060c2565b60405180910390f35b6067600480360381019060639190608f565b6072565b005b60008054905090565b8060008190555050565b60008135905060898160e5565b92915050565b60006020828403121560a057600080fd5b600060ac84828501607c565b91505092915050565b60bc8160db565b82525050565b600060208201905060d5600083018460b5565b92915050565b6000819050919050565b60ec8160db565b811460f657600080fd5b5056fea2646970667358221220f8b1948f74d297fafd90786c1af95e17b6a57ed35fbb91db4ccbaaf5711c59c864736f6c63430008040033")
	contractCallData   = common.Hex2Bytes("cd16ecbf0000000000000000000000000000000000000000000000000000000000000001")

	batchCounterAddress = common.HexToAddress("0000000000000000000000000000000000000200")

	eonKeyBytes    = common.Hex2Bytes("062399E73EE9D77460D6388EDE2C794274BF5F353C36ADA97820D7DA1204D1721404CE5F3E9655C2DB6438F15D86A69573B3A213A103D34DA6D7EC19D192F7F310A89C23C8B6131933992CA47C3B6D888D6BA348F9EEEC7BF4C79BAC0E9D43D4046079D1494829C25147B71DBC859ADCDC6A7BE85EC15CF8EC5A2F4C7B384391")
	eonKey         *shcrypto.EonPublicKey
	decryptionKeys []*shcrypto.EpochSecretKey
)

func init() {
	deployerKey, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	deployerAddress = crypto.PubkeyToAddress(deployerKey.PublicKey)
	sequencerKey, _ = crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000002")
	sequencerAddress = crypto.PubkeyToAddress(sequencerKey.PublicKey)
	userKey, _ = crypto.HexToECDSA("b0057716d5917badaf911b193b12b910811c1497b5bada8d7711f758981c3773")
	userAddress = crypto.PubkeyToAddress(userKey.PublicKey)

	config.BatchCounterAddress = batchCounterAddress
	// address of other contracts set after deployment in prepare

	oracle.SetNodeUrl(nodeUrl)

	// eon key and corresponding decryption keys for epoch 0 to n
	eonKey = new(shcrypto.EonPublicKey)
	err := eonKey.Unmarshal(eonKeyBytes)
	if err != nil {
		panic(err)
	}
	decryptionKeysHex := []string{
		"1E474F87CDC5C95E4E895435496EB551B3995F6CFC5E85BCEF7C6A7978E307C217F8343ACFBD4A9D5B2E1F21A45C8BAB808A4F0A8C25CD4602F9DE0F6BF21ABC",
		"0005F07F07573E9180B0D246B77CB68955228F10D14787830822018AA4F74293258A362765A84AA679F5692E1506CA0EC4E89070A511736780418DF818EC59FC",
		"18AF029337074CA09B8209D8D4E79B803C291FFCBE6FC6E355EDCC05D4E89B0D2A584CD4F885CA946081AE9542497238A0DEAEAE604ED3D2AC0C46FFB9D85AC4",
		"1AF7DE9BE25E5CFEB3D4A98A84FF6E480C8EC6F2CECDD5CBFE019D9789C5DEB42E127937E8F96365DC4C26E184CC29A18967D90AB7844793C6FF4F5C9B65E288",
		"24D546A738B4D24E617E62A1500B94184797A56EA0B74D010E5A927ED55EE00D27DD5EF8B1ABB5DAA61ED80E6E5B94A5A67D171AA4CE9D0261257728C2A509ED",
		"1A7C15E03BC39E6CCEE3B9C6A45892516A9277E4ACB2E45609DA0CA78D92892D16D42AFFDC81C78534156DEF2DD6FBAD90BDAE6826148AB15B324862255F037D",
		"1E8A405828F423F4770841F1ECD71DAB988478D5F95977F51EE0F860B50D5BCD1B789DF57773805DE0D33D76A7C6607CC3E986701B0C0C46227B259567E63952",
		"25BBD96D63C8DB21880DB67299089B10D60BEC4921A2AD0E8168822221BEA51B1B21A805A95DC53C57BBEB88C8686973575A6FB31EA7A1323E5964519830BD5F",
		"1A687857763D89B4A3EFB72C2642451B38E152CB72BC9DE653A4E9DE7A9FD6E0252D262BBA84E3140AE4A755E62892771834521A58E48EF16D93A816CD901410",
		"29B40D793B85F01304F425CABC6AEA1576A30FEA274819ECC73D49E0A6EC3A0B0445B5D34FAAB7881A2FFB9D100475A85DB254B81EA639C9BD853BC79C83534C",
	}
	for _, keyHex := range decryptionKeysHex {
		keyBytes := common.Hex2Bytes(keyHex)
		key := &shcrypto.EpochSecretKey{}
		err := key.Unmarshal(keyBytes)
		if err != nil {
			panic(err)
		}
		decryptionKeys = append(decryptionKeys, key)
	}

	signer = types.LatestSigner(config)
}

func fatalIfError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertTxsSuccessful(t *testing.T, receipts []*types.Receipt, n int) {
	if len(receipts) != n {
		t.Fatalf("expected %d receipts, got %d", n, len(receipts))
	}
	for i, receipt := range receipts {
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("transaction %d failed", i)
		}
	}
}

func assertNoReceiptsNoLogsSomeGasUsed(t *testing.T, receipts []*types.Receipt, logs []*types.Log, gasUsed uint64) {
	if len(receipts) != 0 {
		t.Fatalf("expected no receipts, got %d", len(receipts))
	}
	if len(logs) != 0 {
		t.Fatalf("expected no logs, got %d", len(logs))
	}
	if gasUsed == 0 {
		t.Fatalf("expected tx to consume some gas")
	}
}

func assertBalanceDiff(t *testing.T, balancePre, balancePost, expectedDiff *big.Int) {
	diff := new(big.Int).Sub(balancePost, balancePre)
	if diff.Cmp(expectedDiff) != 0 {
		t.Fatalf("expected balance to change from %d by %d, but changed by %d", balancePre, expectedDiff, diff)
	}
}

func prepare(t *testing.T) *state.StateDB {
	t.Helper()

	oracle.PrefetchBlock(new(big.Int).SetUint64(0), true, nil)
	parent := types.Header{}
	err := rlp.DecodeBytes(oracle.Preimage(genesisHash), &parent)
	fatalIfError(t, err)

	database := state.NewDatabase(parent)
	statedb, err := state.New(parent.Root, database, nil)
	fatalIfError(t, err)

	statedb.SetBalance(deployerAddress, big.NewInt(1000000000000000000))
	statedb.SetBalance(userAddress, big.NewInt(1000000000000000000))

	batchCounterBytecodeHex := batchCounterJSON["deployedBytecode"].(string)
	batchCounterBytecode := common.FromHex(batchCounterBytecodeHex)
	statedb.SetCode(batchCounterAddress, batchCounterBytecode)

	deployEonKey(t, statedb)
	deployCollatorConfig(t, statedb)

	return statedb
}

func makeBatchTx(t *testing.T, statedb *state.StateDB, transactions []*types.Transaction) *types.Transaction {
	return makeBatchTxWithBlockNumber(t, statedb, activationBlockNumber, transactions)
}

func makeBatchTxWithBlockNumber(t *testing.T, statedb *state.StateDB, blockNumber *big.Int, transactions []*types.Transaction) *types.Transaction {
	batchIndex := getBatchIndexTesting(t, statedb)
	txBytes := [][]byte{}
	for _, tx := range transactions {
		b, err := tx.MarshalBinary()
		fatalIfError(t, err)
		txBytes = append(txBytes, b)
	}
	unsignedBatchTx := types.BatchTx{
		ChainID:       config.ChainID,
		DecryptionKey: decryptionKeys[batchIndex].Marshal(),
		BatchIndex:    batchIndex,
		L1BlockNumber: blockNumber,
		Timestamp:     common.Big0,
		Transactions:  txBytes,
	}
	batchTx, err := types.SignNewTx(sequencerKey, signer, &unsignedBatchTx)
	fatalIfError(t, err)
	return batchTx
}

func deployEonKey(t *testing.T, statedb *state.StateDB) {
	t.Helper()

	unsignedDeployTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        nil,
		Value:     common.Big0,
		Data:      common.FromHex(eonKeyStorageJSON["bytecode"].(string)),
	}
	deployTx, err := types.SignNewTx(deployerKey, signer, unsignedDeployTx)
	fatalIfError(t, err)
	deployBatchTx := makeBatchTx(t, statedb, []*types.Transaction{deployTx})
	deployReceipts, _, _, err := processBatchTx(t, statedb, deployBatchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, deployReceipts, 1)
	config.EonKeyBroadcastAddress = deployReceipts[0].ContractAddress

	// insert eon key into storage
	insertEonKeyCalldata, err := eonKeyStorageABI.Pack("insert", eonKeyBytes, uint64(0))
	fatalIfError(t, err)
	unsignedInsertTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        &config.EonKeyBroadcastAddress,
		Value:     common.Big0,
		Data:      insertEonKeyCalldata,
	}
	insertTx, err := types.SignNewTx(deployerKey, signer, unsignedInsertTx)
	fatalIfError(t, err)
	insertBatchTx := makeBatchTx(t, statedb, []*types.Transaction{insertTx})
	insertReceipts, _, _, err := processBatchTx(t, statedb, insertBatchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, insertReceipts, 1)
}

func deployCollatorConfig(t *testing.T, statedb *state.StateDB) {
	t.Helper()

	// deploy addrs seq contract
	unsignedDeployAddrsTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        nil,
		Value:     common.Big0,
		Data:      common.FromHex(addrsSeqJSON["bytecode"].(string)),
	}
	deployAddrsTx, err := types.SignNewTx(deployerKey, signer, unsignedDeployAddrsTx)
	fatalIfError(t, err)
	deployAddrsBatchTx := makeBatchTx(t, statedb, []*types.Transaction{deployAddrsTx})
	deployAddrsReceipts, _, _, err := processBatchTx(t, statedb, deployAddrsBatchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, deployAddrsReceipts, 1)
	addrsSeqAddress := deployAddrsReceipts[0].ContractAddress

	// initialize the addrs seq contract:
	// 1. append empty addrs seq as guard element
	// 2. add collator address to next addrs seq
	// 3. finalize collator addrs seq by appending once more
	appendData, err := addrsSeqABI.Pack("append")
	fatalIfError(t, err)
	unsignedAppendGuardTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        &addrsSeqAddress,
		Value:     common.Big0,
		Data:      appendData,
	}
	appendGuardTx, err := types.SignNewTx(deployerKey, signer, unsignedAppendGuardTx)
	fatalIfError(t, err)
	addData, err := addrsSeqABI.Pack("add", []common.Address{sequencerAddress})
	fatalIfError(t, err)
	unsignedAddTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress) + 1,
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        &addrsSeqAddress,
		Value:     common.Big0,
		Data:      addData,
	}
	addTx, err := types.SignNewTx(deployerKey, signer, unsignedAddTx)
	fatalIfError(t, err)
	unsignedAppendCollatorTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress) + 2,
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        &addrsSeqAddress,
		Value:     common.Big0,
		Data:      appendData,
	}
	appendCollatorTx, err := types.SignNewTx(deployerKey, signer, unsignedAppendCollatorTx)
	fatalIfError(t, err)

	// deploy collator config contract
	collatorConfigBytecode := common.FromHex(collatorConfigJSON["bytecode"].(string))
	collatorConfigDeployArgs, err := collatorConfigABI.Pack("", addrsSeqAddress)
	fatalIfError(t, err)
	unsignedDeployConfigTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress) + 3,
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        nil,
		Value:     common.Big0,
		Data:      append(collatorConfigBytecode, collatorConfigDeployArgs...),
	}
	deployConfigTx, err := types.SignNewTx(deployerKey, signer, unsignedDeployConfigTx)
	fatalIfError(t, err)
	deployConfigBatchTx := makeBatchTx(t, statedb, []*types.Transaction{appendGuardTx, addTx, appendCollatorTx, deployConfigTx})
	deployConfigReceipts, _, _, err := processBatchTx(t, statedb, deployConfigBatchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, deployConfigReceipts, 4)
	config.CollatorConfigListAddress = deployConfigReceipts[3].ContractAddress

	// add collator config
	addConfigArgs, err := collatorConfigABI.Pack("addNewCfg", struct {
		ActivationBlockNumber uint64
		SetIndex              uint64
	}{activationBlockNumber.Uint64(), 1})
	fatalIfError(t, err)
	unsignedAddConfigTx := &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     statedb.GetNonce(deployerAddress),
		GasTipCap: common.Big0,
		GasFeeCap: defaultBaseFee,
		Gas:       10000000,
		To:        &config.CollatorConfigListAddress,
		Value:     common.Big0,
		Data:      addConfigArgs,
	}
	addConfigTx, err := types.SignNewTx(deployerKey, signer, unsignedAddConfigTx)
	fatalIfError(t, err)
	addConfigBatchTx := makeBatchTxWithBlockNumber(t, statedb, common.Big0, []*types.Transaction{addConfigTx})
	addConfigReceipts, _, _, err := processBatchTx(t, statedb, addConfigBatchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, addConfigReceipts, 1)
}

func processBatchTx(t *testing.T, statedb *state.StateDB, batchTx *types.Transaction) (types.Receipts, []*types.Log, uint64, error) {
	return processBatchTxWithFee(t, statedb, batchTx, defaultBaseFee)
}

func processBatchTxWithFee(t *testing.T, statedb *state.StateDB, batchTx *types.Transaction, baseFee *big.Int) (types.Receipts, []*types.Log, uint64, error) {
	t.Helper()

	if batchTx.Type() != types.BatchTxType {
		t.Fatal("got non batch tx")
	}

	parent := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: common.Big1,
		Number:     common.Big0,
		GasLimit:   100000000,
		// GasUsed     uint64
		Time:      0,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: baseFee,
	}
	header := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: parent.Difficulty,
		Number:     new(big.Int).Add(parent.Number, big.NewInt(1)),
		GasLimit:   parent.GasLimit,
		// GasUsed     uint64
		Time:      parent.Time,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: baseFee,
	}
	vmconfig := vm.Config{NoBaseFee: true}
	bc := NewBlockChain(&parent)
	block := types.NewBlock(&header, []*types.Transaction{batchTx}, nil, nil, trie.NewStackTrie(nil))

	processor := NewStateProcessor(config, bc, bc.Engine())
	receipts, logs, gasUsed, err := processor.Process(block, statedb, vmconfig)
	return receipts, logs, gasUsed, err
}

func encryptPayload(t *testing.T, payload *types.DecryptedPayload, batchIndex uint64) []byte {
	t.Helper()

	payloadEncoded, err := rlp.EncodeToBytes(payload)
	fatalIfError(t, err)

	epochId := shcrypto.ComputeEpochID(batchIndex)
	sigma, err := shcrypto.RandomSigma(rand.Reader)
	fatalIfError(t, err)
	encryptedPayload := shcrypto.Encrypt(payloadEncoded, eonKey, epochId, sigma)

	return encryptedPayload.Marshal()
}

func getBatchIndexTesting(t *testing.T, statedb *state.StateDB) uint64 {
	t.Helper()
	header := &types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: common.Big1,
		Number:     common.Big0,
		GasLimit:   100000000,
		// GasUsed     uint64
		Time:      0,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: defaultBaseFee,
	}
	bc := NewBlockChain(header)
	blockContext := NewEVMBlockContext(header, bc, nil)
	vmconfig := vm.Config{NoBaseFee: true}
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, vmconfig)
	batchIndex, err := getBatchIndex(vmenv, config.BatchCounterAddress)
	fatalIfError(t, err)
	return batchIndex
}

func TestEmptyBlock(t *testing.T) {
	statedb := prepare(t)

	parent := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: common.Big1,
		Number:     common.Big0,
		GasLimit:   100000000,
		// GasUsed     uint64
		Time:      0,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: defaultBaseFee,
	}
	header := types.Header{
		ParentHash: common.Hash{},
		// UncleHash   common.Hash
		Coinbase: sequencerAddress,
		// Root        common.Hash
		// TxHash      common.Hash
		// ReceiptHash common.Hash
		Bloom:      types.Bloom{},
		Difficulty: parent.Difficulty,
		Number:     new(big.Int).Add(parent.Number, big.NewInt(1)),
		GasLimit:   parent.GasLimit,
		// GasUsed     uint64
		Time:      parent.Time,
		Extra:     []byte{},
		MixDigest: common.Hash{},
		Nonce:     types.BlockNonce{},

		BaseFee: defaultBaseFee,
	}
	block := types.NewBlock(&header, []*types.Transaction{}, nil, nil, trie.NewStackTrie(nil))

	vmconfig := vm.Config{NoBaseFee: true}
	bc := NewBlockChain(&parent)
	processor := NewStateProcessor(config, bc, bc.Engine())
	_, _, _, err := processor.Process(block, statedb, vmconfig)
	if err == nil {
		t.Fatal()
	}
}

func TestEmptyBatch(t *testing.T) {
	statedb := prepare(t)
	batchTx := makeBatchTx(t, statedb, []*types.Transaction{})
	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	fatalIfError(t, err)
	if len(receipts) != 0 {
		t.Fatalf("expected no receipts, got %d", len(receipts))
	}
	if len(logs) != 0 {
		t.Fatalf("expected no logs, got %d", len(logs))
	}
	if gasUsed != 0 {
		t.Fatalf("expected tx to consume zero gas")
	}
}

func TestEmptyShutterTx(t *testing.T) {
	statedb := prepare(t)
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            0,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        defaultBaseFee,
		Gas:              21000,
		EncryptedPayload: []byte{},
		BatchIndex:       getBatchIndexTesting(t, statedb),
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	fatalIfError(t, err)
	batchTx := makeBatchTx(t, statedb, []*types.Transaction{shutterTx})

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	fatalIfError(t, err)
	if len(receipts) != 0 {
		t.Fatalf("expected no receipts, got %d", len(receipts))
	}
	if len(logs) != 0 {
		t.Fatalf("expected no logs, got %d", len(logs))
	}
	if gasUsed != 0 {
		t.Fatalf("expected tx to consume no gas")
	}
}

func TestEmptyShutterTxWithFee(t *testing.T) {
	statedb := prepare(t)

	txGas := uint64(30000)
	tests := []struct {
		name           string
		txGasTipCap    *big.Int
		txGasFeeCap    *big.Int
		blockBaseFee   *big.Int
		expectedFee    *big.Int
		expectedReward *big.Int
		blockValid     bool
	}{
		{
			name:           "only base fee",
			txGasTipCap:    common.Big0,
			txGasFeeCap:    big.NewInt(600),
			blockBaseFee:   big.NewInt(500),
			expectedFee:    new(big.Int).Mul(big.NewInt(500), new(big.Int).SetUint64(txGas)),
			expectedReward: common.Big0,
			blockValid:     true,
		},
		{
			name:           "only tip fee",
			txGasTipCap:    big.NewInt(500),
			txGasFeeCap:    big.NewInt(500),
			blockBaseFee:   common.Big0,
			expectedFee:    new(big.Int).Mul(big.NewInt(500), new(big.Int).SetUint64(txGas)),
			expectedReward: new(big.Int).Mul(big.NewInt(500), new(big.Int).SetUint64(txGas)),
			blockValid:     true,
		},
		{
			name:           "base and tip fee",
			txGasTipCap:    big.NewInt(200),
			txGasFeeCap:    big.NewInt(600),
			blockBaseFee:   big.NewInt(500),
			expectedFee:    new(big.Int).Mul(big.NewInt(600), new(big.Int).SetUint64(txGas)),
			expectedReward: new(big.Int).Mul(big.NewInt(100), new(big.Int).SetUint64(txGas)),
			blockValid:     true,
		},
		{
			name:         "invalid tip > cap",
			txGasTipCap:  big.NewInt(100),
			txGasFeeCap:  common.Big0,
			blockBaseFee: common.Big0,
			blockValid:   false,
		},
		{
			name:         "invalid fee cap < base fee",
			txGasTipCap:  common.Big0,
			txGasFeeCap:  big.NewInt(99),
			blockBaseFee: big.NewInt(100),
			blockValid:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unsignedShutterTx := &types.ShutterTx{
				ChainID:          config.ChainID,
				Nonce:            statedb.GetNonce(userAddress),
				GasTipCap:        tc.txGasTipCap,
				GasFeeCap:        tc.txGasFeeCap,
				Gas:              txGas,
				EncryptedPayload: []byte{},
			}
			shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
			if err != nil {
				t.Fatal(err)
			}

			userBalancePre := statedb.GetBalance(userAddress)
			sequencerBalancePre := statedb.GetBalance(sequencerAddress)

			batchTx := makeBatchTx(t, statedb, []*types.Transaction{shutterTx})
			receipts, logs, gasUsed, err := processBatchTxWithFee(t, statedb, batchTx, tc.blockBaseFee)

			if !tc.blockValid {
				if err == nil {
					t.Fatalf("expected error when processing block")
				}
			} else {
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
				sequencerBalancePost := statedb.GetBalance(sequencerAddress)
				blockReward := big.NewInt(5000000000000000000)
				expectedSequencerDiff := new(big.Int).Add(tc.expectedReward, blockReward)

				assertBalanceDiff(t, userBalancePre, userBalancePost, new(big.Int).Neg(tc.expectedFee))
				assertBalanceDiff(t, sequencerBalancePre, sequencerBalancePost, expectedSequencerDiff)
			}
		})
	}
}

func TestTransfer(t *testing.T) {
	statedb := prepare(t)

	receiver := common.HexToAddress("2222222222222222222222222222222222222222")
	amount := big.NewInt(100)
	payload := &types.DecryptedPayload{
		To:    &receiver,
		Value: amount,
		Data:  []byte{},
	}
	batchIndex := getBatchIndexTesting(t, statedb)
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        defaultBaseFee,
		Gas:              21000,
		EncryptedPayload: encryptPayload(t, payload, batchIndex),
		BatchIndex:       batchIndex,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	fatalIfError(t, err)
	batchTx := makeBatchTx(t, statedb, []*types.Transaction{shutterTx})

	senderBalancePre := statedb.GetBalance(userAddress)
	receiverBalancePre := statedb.GetBalance(receiver)

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, receipts, 1)
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 21000 {
		t.Fatalf("expected 21000 gas used, got %d", gasUsed)
	}

	fee := new(big.Int).Mul(defaultBaseFee, new(big.Int).SetUint64(gasUsed))
	amountPlusFee := new(big.Int).Add(amount, fee)

	senderBalancePost := statedb.GetBalance(userAddress)
	receiverBalancePost := statedb.GetBalance(receiver)
	assertBalanceDiff(t, senderBalancePre, senderBalancePost, new(big.Int).Neg(amountPlusFee))
	assertBalanceDiff(t, receiverBalancePre, receiverBalancePost, amount)
}

func TestContractCall(t *testing.T) {
	statedb := prepare(t)

	deployPayload := &types.DecryptedPayload{
		To:    nil,
		Value: big.NewInt(0),
		Data:  contractDeployData,
	}
	batchIndex := getBatchIndexTesting(t, statedb)
	unsignedDeployTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        defaultBaseFee,
		Gas:              1000000,
		EncryptedPayload: encryptPayload(t, deployPayload, batchIndex),
		BatchIndex:       batchIndex,
	}

	contractAddress := common.HexToAddress("0xFA33c8EF8b5c4f3003361c876a298D1DB61ccA4e")
	callPayload := &types.DecryptedPayload{
		To:    &contractAddress,
		Value: big.NewInt(0),
		Data:  contractCallData,
	}
	unsignedCallTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress) + 1,
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        defaultBaseFee,
		Gas:              100000,
		EncryptedPayload: encryptPayload(t, callPayload, batchIndex),
		BatchIndex:       batchIndex,
	}

	deployTx, err := types.SignNewTx(userKey, signer, unsignedDeployTx)
	fatalIfError(t, err)
	callTx, err := types.SignNewTx(userKey, signer, unsignedCallTx)
	fatalIfError(t, err)
	batchTx := makeBatchTx(t, statedb, []*types.Transaction{
		deployTx,
		callTx,
	})

	receipts, logs, _, err := processBatchTx(t, statedb, batchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, receipts, 2)
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
}

func TestContractDeployment(t *testing.T) {
	statedb := prepare(t)

	payload := &types.DecryptedPayload{
		To:    nil,
		Value: big.NewInt(0),
		Data:  contractDeployData,
	}
	batchIndex := getBatchIndexTesting(t, statedb)
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        defaultBaseFee,
		Gas:              1000000,
		EncryptedPayload: encryptPayload(t, payload, batchIndex),
		BatchIndex:       batchIndex,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	fatalIfError(t, err)
	batchTx := makeBatchTx(t, statedb, []*types.Transaction{shutterTx})

	receipts, logs, _, err := processBatchTx(t, statedb, batchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, receipts, 1)
	if bytes.Equal(receipts[0].ContractAddress.Bytes(), common.Address{}.Bytes()) {
		t.Fatal("should have deployed contract")
	}
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}

	code := statedb.GetCode(receipts[0].ContractAddress)
	if len(code) == 0 {
		t.Fatal("should have deployed contract")
	}
}

func TestGetEonKey(t *testing.T) {
	statedb := prepare(t)

	// mine empty block to test the verification of eon key
	_, _, _, err := processBatchTx(t, statedb, makeBatchTx(t, statedb, []*types.Transaction{}))
	fatalIfError(t, err)
}

func TestPlaintextTx(t *testing.T) {
	// Tests that a plaintext tx is properly executed after a ciphertext tx
	statedb := prepare(t)

	receiver := common.HexToAddress("2222222222222222222222222222222222222222")
	amount := big.NewInt(100)
	payload := &types.DecryptedPayload{
		To:    &receiver,
		Value: amount,
		Data:  []byte{},
	}
	batchIndex := getBatchIndexTesting(t, statedb)
	unsignedShutterTx := &types.ShutterTx{
		ChainID:          config.ChainID,
		Nonce:            statedb.GetNonce(userAddress),
		GasTipCap:        big.NewInt(0),
		GasFeeCap:        defaultBaseFee,
		Gas:              21000,
		EncryptedPayload: encryptPayload(t, payload, batchIndex),
		BatchIndex:       batchIndex,
	}
	shutterTx, err := types.SignNewTx(userKey, signer, unsignedShutterTx)
	fatalIfError(t, err)
	unsignedPlainTx := &types.LegacyTx{
		Nonce:    statedb.GetNonce(userAddress) + 1,
		GasPrice: defaultBaseFee,
		Gas:      21000,
		To:       &receiver,
		Value:    amount,
	}
	plainTx, err := types.SignNewTx(userKey, signer, unsignedPlainTx)
	fatalIfError(t, err)
	batchTx := makeBatchTx(t, statedb, []*types.Transaction{shutterTx, plainTx})

	senderBalancePre := statedb.GetBalance(userAddress)
	receiverBalancePre := statedb.GetBalance(receiver)

	receipts, logs, gasUsed, err := processBatchTx(t, statedb, batchTx)
	fatalIfError(t, err)
	assertTxsSuccessful(t, receipts, 2)
	if len(logs) != 0 {
		t.Fatal("expected 0 logs")
	}
	if gasUsed != 42000 {
		t.Fatalf("expected 42000 gas used, got %d", gasUsed)
	}

	senderBalancePost := statedb.GetBalance(userAddress)
	receiverBalancePost := statedb.GetBalance(receiver)
	transferAmount := new(big.Int).Mul(amount, common.Big2)
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), defaultBaseFee)
	amountPlusFee := new(big.Int).Add(transferAmount, fee)
	assertBalanceDiff(t, senderBalancePre, senderBalancePost, new(big.Int).Neg(amountPlusFee))
	assertBalanceDiff(t, receiverBalancePre, receiverBalancePost, transferAmount)
}

func TestWrongBatchIndex(t *testing.T) {
	statedb := prepare(t)
	batchIndex := getBatchIndexTesting(t, statedb) + 1
	unsignedBatchTx := types.BatchTx{
		ChainID:       config.ChainID,
		DecryptionKey: decryptionKeys[batchIndex].Marshal(),
		BatchIndex:    batchIndex,
		L1BlockNumber: common.Big0,
		Timestamp:     common.Big0,
		Transactions:  [][]byte{},
	}
	batchTx, err := types.SignNewTx(sequencerKey, signer, &unsignedBatchTx)
	fatalIfError(t, err)
	_, _, _, err = processBatchTx(t, statedb, batchTx)
	if err == nil {
		t.Fatal("batch tx with batch index too large was not rejected")
	}

	batchIndex -= 2
	unsignedBatchTx.BatchIndex = batchIndex
	unsignedBatchTx.DecryptionKey = decryptionKeys[batchIndex].Marshal()
	batchTx, err = types.SignNewTx(sequencerKey, signer, &unsignedBatchTx)
	fatalIfError(t, err)
	_, _, _, err = processBatchTx(t, statedb, batchTx)
	if err == nil {
		t.Fatal("batch tx with batch index too small was not rejected")
	}
}

func TestSignatureCheck(t *testing.T) {
	statedb := prepare(t)
	batchIndex := getBatchIndexTesting(t, statedb)
	unsignedBatchTx := types.BatchTx{
		ChainID:       config.ChainID,
		DecryptionKey: decryptionKeys[batchIndex].Marshal(),
		BatchIndex:    batchIndex,
		L1BlockNumber: activationBlockNumber,
		Timestamp:     common.Big0,
		Transactions:  [][]byte{},
	}

	batchTx, err := types.SignNewTx(userKey, signer, &unsignedBatchTx)
	fatalIfError(t, err)
	_, _, _, err = processBatchTx(t, statedb, batchTx)
	if err == nil {
		t.Fatal("batch tx with wrong signature was not rejected")
	}
}
