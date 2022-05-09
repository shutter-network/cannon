// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var eonKeyStorageAbi abi.ABI

func init() {
	def := `[{ "name": "method", "type": "function", "outputs": [{"type": "bytes"}]}]`
	eonKeyStorageAbi, _ = abi.JSON(strings.NewReader(def))
}

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	blockContext := NewEVMBlockContext(header, p.bc, nil)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)
	signer := types.MakeSigner(p.config, header.Number)

	// we expect blocks to consist of exactly one batch tx
	if len(block.Transactions()) != 1 {
		return nil, nil, 0, fmt.Errorf("block does not contain exactly one transaction")
	}
	if block.Transactions()[0].Type() != types.BatchTxType {
		return nil, nil, 0, fmt.Errorf("transaction is not batch tx")
	}
	batchTx := block.Transactions()[0]
	log.Printf("processing batch #%d", batchTx.BatchIndex())

	// check chain id
	if p.bc.chainConfig.ChainID.Cmp(batchTx.ChainId()) != 0 {
		return nil, nil, 0, fmt.Errorf(
			"batch has incorrect chain id %d instead of %d",
			batchTx.ChainId(),
			p.bc.chainConfig.ChainID,
		)
	}

	// check and increment batch index
	err := checkBatchIndex(vmenv, p.config.BatchCounterAddress, batchTx.BatchIndex())
	if err != nil {
		return nil, nil, 0, err
	}
	incrementBatchIndexMsg := makeIncrementBatchIndexMessage(blockContext, statedb, p.config, cfg)
	incrementBatchIndexTx := types.NewTransaction(
		incrementBatchIndexMsg.Nonce(),    // nonce
		*incrementBatchIndexMsg.To(),      // to
		incrementBatchIndexMsg.Value(),    // amount
		incrementBatchIndexMsg.Gas(),      // gas limit
		incrementBatchIndexMsg.GasPrice(), // gas price
		incrementBatchIndexMsg.Data(),     // data
	)
	receipt, err := applyTransaction(
		incrementBatchIndexMsg,
		p.config,
		p.bc,
		nil,
		gp,
		statedb,
		blockNumber,
		blockHash,
		incrementBatchIndexTx,
		new(uint64), // gas used (we don't care about that here)
		vmenv,
	)
	if err != nil {
		return nil, nil, 0, err
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, nil, 0, fmt.Errorf("batch index increment message failed")
	}

	// Check the decryption key against the eon key in the eon key storage contract (unless the
	// keypers have not published a key yet)
	decryptionKey := &shcrypto.EpochSecretKey{}
	err = decryptionKey.Unmarshal(batchTx.DecryptionKey())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("decryption key is invalid")
	}
	blankTxContext := vm.TxContext{Origin: common.Address{}, GasPrice: common.Big0}
	e := vm.NewEVM(blockContext, blankTxContext, statedb, p.config, cfg)
	eonKey, err := getEonKeyFromContract(e, p.config.EonKeyBroadcastAddress, batchTx.L1BlockNumber())
	if err != nil {
		return nil, nil, 0, err
	}
	if eonKey != nil {
		ok, err := shcrypto.VerifyEpochSecretKey(decryptionKey, eonKey, batchTx.BatchIndex())
		if err != nil {
			return nil, nil, 0, err
		}
		if !ok {
			return nil, nil, 0, fmt.Errorf("decryption key is not correct for batch %d", batchTx.BatchIndex())
		}
	}

	// check batch signature
	// TODO

	// check l1BlockNumber and timestamp
	// TODO

	// unmarshal transactions
	transactions := []*types.Transaction{}
	for i, txBytes := range batchTx.Transactions() {
		tx := new(types.Transaction)
		err := tx.UnmarshalBinary(txBytes)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("batch tx contains invalid transaction at index %d: %s", i, err)
		}
		if tx.Type() == types.BatchTxType {
			return nil, nil, 0, fmt.Errorf("batch tx contains batch tx at index %d", i)
		}
		transactions = append(transactions, tx)
	}

	// Execute the envelopes of shutter txs if we found the eon key. Remember for which
	// transaction the fee has been paid successfully, because this is a precondition for
	// executing them later.
	feePaid := make(map[int]bool)
	if eonKey != nil {
		coinbase := block.Coinbase()
		for i, tx := range transactions {
			feePaid[i] = false
			if tx.Type() != types.ShutterTxType {
				continue
			}
			sender, err := signer.Sender(tx)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not extract signer of tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			gasPrice := math.BigMin(new(big.Int).Add(tx.GasTipCap(), header.BaseFee), tx.GasFeeCap())
			gasFee := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(tx.Gas()))

			balance := statedb.GetBalance(sender)
			if balance.Cmp(gasFee) > 0 {
				statedb.SubBalance(sender, gasFee)
				statedb.AddBalance(coinbase, gasFee)
				feePaid[i] = true
			}
		}
	}

	// execute transactions
	for i, tx := range transactions {
		var msg types.Message
		if tx.Type() == types.ShutterTxType {
			// Decrypt shutter txs if they paid the transaction fee.
			if !feePaid[i] {
				fmt.Printf("skipping execution of tx %d [%v] as it didn't pay the fee\n", i, tx.Hash().Hex())
				continue
			}
			decryptedPayload, err := decryptPayload(tx.EncryptedPayload(), decryptionKey)
			if err != nil {
				fmt.Printf("could not decrypt tx %d [%v]: %s\n", i, tx.Hash().Hex(), err)
				continue
			}
			msg, err = decryptedPayload.AsMessage(tx, signer)
			if err != nil {
				fmt.Printf("could not convert decrypted tx %d into msg [%v]: %s\n", i, tx.Hash().Hex(), err)
				continue
			}
		} else {
			msg, err = tx.AsMessage(types.MakeSigner(p.config, header.Number), header.BaseFee)
			if err != nil {
				return nil, nil, 0, fmt.Errorf(
					"could not convert tx %d into msg [%v]: %w",
					i,
					tx.Hash().Hex(),
					err,
				)
			}
		}

		// execute transaction
		statedb.Prepare(tx.Hash(), i)
		receipt, err := applyTransaction(
			msg,
			p.config,
			p.bc,
			nil,
			gp,
			statedb,
			blockNumber,
			blockHash,
			tx,
			usedGas,
			vmenv,
		)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

	return receipts, allLogs, *usedGas, nil
}

func getEonKeyFromContract(e *vm.EVM, eonKeyContract common.Address, blockNumber *big.Int) (*shcrypto.EonPublicKey, error) {
	caller := vm.AccountRef(common.Address{})

	selector := crypto.Keccak256([]byte("get(uint64)"))[:4]
	paddedBlk := common.BigToHash(blockNumber)
	callData := append(selector, paddedBlk.Bytes()...)

	result, _, err := e.Call(caller, eonKeyContract, callData, 1000000, common.Big0)
	if err != nil {
		log.Printf("failed to find eon key for block #%s: %s", blockNumber, err)
		return nil, nil
	}
	if len(result) == 0 {
		log.Printf("no eon key available for block #%s", blockNumber)
		return nil, nil
	}

	// decode result with abi
	decoded, err := eonKeyStorageAbi.Unpack("method", result)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 1 {
		return nil, fmt.Errorf("decoded multiple outputs with eon key storage abi")
	}
	var ok bool
	eonKeyBytes, ok := decoded[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("could not decode bytes out of eon key output")
	}

	eonKey := &shcrypto.EonPublicKey{}
	err = eonKey.Unmarshal(eonKeyBytes)
	if err != nil {
		return nil, err
	}

	return eonKey, nil
}

// getBatchIndex returns the current batch index in the batch counter contract.
func getBatchIndex(e *vm.EVM, batchCounterContract common.Address) (uint64, error) {
	caller := vm.AccountRef(common.Address{})
	selector := crypto.Keccak256([]byte("batchIndex()"))[:4]
	result, _, err := e.Call(caller, batchCounterContract, selector, 1000000, common.Big0)
	if err != nil {
		return 0, err
	}

	resultBig := new(big.Int).SetBytes(result)
	resultUint64 := resultBig.Uint64()
	if new(big.Int).SetUint64(resultUint64).Cmp(resultBig) != 0 {
		return 0, fmt.Errorf("get batch index contract call result is not a uint64")
	}
	return resultUint64, nil
}

// checkBatchIndex checks that the current batch counter value equals the given batch index.
func checkBatchIndex(e *vm.EVM, batchCounterContract common.Address, batchIndex uint64) error {
	currentBatchIndex, err := getBatchIndex(e, batchCounterContract)
	if err != nil {
		return nil
	}
	if currentBatchIndex != batchIndex {
		return fmt.Errorf("expected batch #%d, but got batch #%d", currentBatchIndex, batchIndex)
	}
	return nil
}

func makeIncrementBatchIndexMessage(blockCtx vm.BlockContext, statedb vm.StateDB, chainConfig *params.ChainConfig, config vm.Config) types.Message {
	nonce := statedb.GetNonce(common.Address{})
	selector := crypto.Keccak256([]byte("increment()"))[:4]
	return types.NewMessage(
		common.Address{},                 // from
		&chainConfig.BatchCounterAddress, // to
		nonce,                            // nonce
		common.Big0,                      // amount
		1000000,                          // gas limit
		common.Big0,                      // gas price
		common.Big0,                      // gas fee cap
		common.Big0,                      // gas tip cap
		selector,                         // data
		nil,                              // access list
		false,                            // fake
	)
}

func decryptPayload(encryptedPayloadBytes []byte, decryptionKey *shcrypto.EpochSecretKey) (*types.DecryptedPayload, error) {
	encryptedPayload := shcrypto.EncryptedMessage{}
	err := encryptedPayload.Unmarshal(encryptedPayloadBytes)
	if err != nil {
		return nil, err
	}

	decryptedPayloadBytes, err := encryptedPayload.Decrypt(decryptionKey)
	if err != nil {
		return nil, err
	}

	var decryptedPayload types.DecryptedPayload
	err = rlp.DecodeBytes(decryptedPayloadBytes, &decryptedPayload)
	if err != nil {
		return nil, err
	}
	return &decryptedPayload, nil
}

func applyTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	return applyTransaction(msg, config, bc, author, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}
