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
	"reflect"

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
		coinbase    = block.Coinbase()
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
	incrementBatchIndexMsg, err := makeIncrementBatchIndexMessage(blockContext, statedb, p.config, cfg)
	if err != nil {
		return nil, nil, 0, err
	}
	incrementBatchIndexTx := types.NewTransaction(
		incrementBatchIndexMsg.Nonce(),    // nonce
		*incrementBatchIndexMsg.To(),      // to
		incrementBatchIndexMsg.Value(),    // amount
		incrementBatchIndexMsg.Gas(),      // gas limit
		incrementBatchIndexMsg.GasPrice(), // gas price
		incrementBatchIndexMsg.Data(),     // data
	)
	batchIndexIncrementGas := uint64(0)
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
		&batchIndexIncrementGas,
		vmenv,
	)
	if err != nil {
		return nil, nil, 0, err
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, nil, 0, fmt.Errorf("batch index increment message failed")
	}
	batchIndexIncrementFee := new(big.Int).Mul(new(big.Int).SetUint64(batchIndexIncrementGas), header.BaseFee)
	statedb.AddBalance(coinbase, batchIndexIncrementFee) // refund sequencer for incrementing batch index

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
	var processShutterTxs bool
	if eonKey != nil {
		processShutterTxs = true
		ok, err := shcrypto.VerifyEpochSecretKey(decryptionKey, eonKey, batchTx.BatchIndex())
		if err != nil {
			return nil, nil, 0, err
		}
		if !ok {
			return nil, nil, 0, fmt.Errorf("decryption key is not correct for batch %d", batchTx.BatchIndex())
		}
	} else {
		processShutterTxs = false
	}

	// check batch signature (if the collator config contract has been deployed yet)
	batchTxSigner, err := signer.Sender(batchTx)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid batch signature: %s", err)
	}
	collatorAddress, err := getCollatorAddress(e, p.config.CollatorConfigListAddress, batchTx.L1BlockNumber())
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get collator address from config list contract: %s", err)
	}
	log.Printf("collator for block #%d: %s", batchTx.L1BlockNumber(), collatorAddress)
	if collatorAddress != nil && batchTxSigner != *collatorAddress {
		return nil, nil, 0, fmt.Errorf("batch was signed by %s instead of collator %s (at mainchain block %d)", batchTxSigner, collatorAddress, batchTx.L1BlockNumber())
	}

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

	// Execute the envelopes of shutter txs if we found the eon key.
	if processShutterTxs {
		for i, tx := range transactions {
			if tx.Type() != types.ShutterTxType {
				continue
			}
			sender, err := signer.Sender(tx)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not extract signer of tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}

			if tx.Gas() < params.TxGas {
				return nil, nil, 0, fmt.Errorf("invalid tx %d [%v]: tx gas lower than minimum (%v < %v)", i, tx.Hash(), tx.Gas(), params.TxGas)
			}
			if tx.GasFeeCap().Cmp(tx.GasTipCap()) < 0 {
				return nil, nil, 0, fmt.Errorf("invalid tx %d [%v]: gas fee cap lower than gas tip cap (%v < %v)", i, tx.Hash(), tx.GasFeeCap(), tx.GasTipCap())
			}
			if tx.GasFeeCap().Cmp(header.BaseFee) < 0 {
				return nil, nil, 0, fmt.Errorf("invalid tx %d [%v]: gas fee cap lower than header base fee (%v < %v)", i, tx.Hash(), tx.GasFeeCap(), header.BaseFee)
			}

			priorityFeeGasPrice := math.BigMin(tx.GasTipCap(), new(big.Int).Sub(tx.GasFeeCap(), header.BaseFee))
			priorityFee := new(big.Int).Mul(priorityFeeGasPrice, new(big.Int).SetUint64(tx.Gas()))
			gasPrice := new(big.Int).Add(priorityFeeGasPrice, header.BaseFee)
			gasFee := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(tx.Gas()))

			balance := statedb.GetBalance(sender)
			if balance.Cmp(gasFee) < 0 {
				return nil, nil, 0, fmt.Errorf("invalid tx %d [%v]: cannot pay for gas", i, tx.Hash())
			}
			statedb.SubBalance(sender, gasFee)
			statedb.AddBalance(coinbase, priorityFee)
		}
	}

	// execute transactions
	for i, tx := range transactions {
		if tx.Type() == types.ShutterTxType && !processShutterTxs {
			continue
		}

		sender, err := signer.Sender(tx)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not extract signer of tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		// Manually check the nonce. This is redundant for all txs that actually get applied,
		// but not for Shutter txs that fail to get decrypted.
		accountNonce := statedb.GetNonce(sender)
		if tx.Nonce() != accountNonce {
			return nil, nil, 0, fmt.Errorf("invalid tx %d [%v]: tx nonce does not match account nonce (%d != %d)", i, tx.Hash(), tx.Nonce(), accountNonce)
		}

		var msg types.Message
		if tx.Type() == types.ShutterTxType {
			decryptedPayload, err := decryptPayload(tx.EncryptedPayload(), decryptionKey)
			if err != nil {
				fmt.Printf("could not decrypt tx %d [%v]: %s\n", i, tx.Hash().Hex(), err)
				statedb.SetNonce(sender, tx.Nonce()+1)
				continue
			}
			msg, err = decryptedPayload.AsMessage(tx, signer)
			if err != nil {
				fmt.Printf("could not convert decrypted tx %d into msg [%v]: %s\n", i, tx.Hash().Hex(), err)
				statedb.SetNonce(sender, tx.Nonce()+1)
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

	callData, err := eonKeyStorageABI.Pack("get", blockNumber.Uint64())
	if err != nil {
		return nil, err
	}
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
	decoded, err := eonKeyStorageABI.Unpack("get", result)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 1 {
		return nil, fmt.Errorf("decoded multiple outputs with eon key storage abi")
	}
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
	callData, err := batchCounterABI.Pack("batchIndex")
	if err != nil {
		return 0, err
	}
	result, _, err := e.Call(caller, batchCounterContract, callData, 1000000, common.Big0)
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

// getCollatorAddress returns the address configured as the collator in the collator config
// contract for the given L1 block number. If the contract hasn't been deployed yet, it returns
// nil.
func getCollatorAddress(e *vm.EVM, collatorConfigContract common.Address, blockNumber *big.Int) (*common.Address, error) {
	if e.StateDB.GetCodeSize(collatorConfigContract) == 0 {
		return nil, nil
	}

	caller := vm.AccountRef(common.Address{})
	configData, err := collatorConfigABI.Pack("getActiveConfig", blockNumber.Uint64())
	if err != nil {
		return nil, err
	}
	configResult, _, err := e.Call(caller, collatorConfigContract, configData, 1000000, common.Big0)
	if err != nil {
		return nil, fmt.Errorf("failed to get active collator config index: %s", err)
	}
	configReturnValues, err := collatorConfigABI.Unpack("getActiveConfig", configResult)
	if err != nil {
		return nil, err
	}
	if len(configReturnValues) != 1 {
		return nil, fmt.Errorf("expected getActiveConfig to return 1 value, got %d", len(configReturnValues))
	}
	setIndex := reflect.ValueOf(configReturnValues[0]).FieldByName("SetIndex").Uint()
	if setIndex == 0 {
		// Set index 0 is used as a guard element and contains no addresses. If this is the active
		// config, no real config has been deployed yet. We return nil to signal that, similar to
		// what we'd do if the collator config contract hasn't been deployed yet at all.
		return nil, nil
	}

	addrsSeqData, err := collatorConfigABI.Pack("addrsSeq")
	if err != nil {
		return nil, err
	}
	addrsSeqResult, _, err := e.Call(caller, collatorConfigContract, addrsSeqData, 1000000, common.Big0)
	if err != nil {
		return nil, err
	}
	addrsSeqReturnValues, err := collatorConfigABI.Unpack("addrsSeq", addrsSeqResult)
	if err != nil {
		return nil, err
	}
	if len(addrsSeqReturnValues) != 1 {
		return nil, fmt.Errorf("expected addrsSeq call to return one value, got %d", len(addrsSeqReturnValues))
	}
	addrsSeqAddress, ok := addrsSeqReturnValues[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("expected addrsSeq call to return address")
	}

	atData, err := addrsSeqABI.Pack("at", setIndex, uint64(0))
	if err != nil {
		return nil, err
	}
	atResult, _, err := e.Call(caller, addrsSeqAddress, atData, 1000000, common.Big0)
	if err != nil {
		return nil, err
	}
	atReturnValues, err := addrsSeqABI.Unpack("at", atResult)
	if err != nil {
		return nil, err
	}
	if len(atReturnValues) != 1 {
		return nil, fmt.Errorf("expected exactly one return value, got %d", len(atReturnValues))
	}
	collator, ok := atReturnValues[0].(common.Address)
	if !ok {
		return nil, fmt.Errorf("could not decode at return value as address")
	}
	return &collator, nil
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

func makeIncrementBatchIndexMessage(blockCtx vm.BlockContext, statedb vm.StateDB, chainConfig *params.ChainConfig, config vm.Config) (types.Message, error) {
	nonce := statedb.GetNonce(common.Address{})
	callData, err := batchCounterABI.Pack("increment")
	if err != nil {
		return types.Message{}, err
	}
	return types.NewMessage(
		common.Address{},                 // from
		&chainConfig.BatchCounterAddress, // to
		nonce,                            // nonce
		common.Big0,                      // amount
		1000000,                          // gas limit
		common.Big0,                      // gas price
		common.Big0,                      // gas fee cap
		common.Big0,                      // gas tip cap
		callData,                         // data
		nil,                              // access list
		false,                            // fake
	), nil
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
