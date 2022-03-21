// Copyright 2021 The go-ethereum Authors
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

package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type DecryptionKeyTx struct {
	ChainID       *big.Int
	DecryptionKey []byte
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *DecryptionKeyTx) copy() TxData {
	cpy := &DecryptionKeyTx{
		ChainID:       tx.ChainID,
		DecryptionKey: []byte{},
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.DecryptionKey != nil {
		cpy.DecryptionKey = make([]byte, len(tx.DecryptionKey))
		copy(cpy.DecryptionKey, tx.DecryptionKey)
	}
	return cpy
}

// accessors for innerTx.
func (tx *DecryptionKeyTx) txType() byte             { return DynamicFeeTxType }
func (tx *DecryptionKeyTx) chainID() *big.Int        { return tx.ChainID }
func (tx *DecryptionKeyTx) protected() bool          { return true }
func (tx *DecryptionKeyTx) accessList() AccessList   { return nil }
func (tx *DecryptionKeyTx) data() []byte             { return nil }
func (tx *DecryptionKeyTx) gas() uint64              { return 0 }
func (tx *DecryptionKeyTx) gasFeeCap() *big.Int      { return big.NewInt(0) }
func (tx *DecryptionKeyTx) gasTipCap() *big.Int      { return big.NewInt(0) }
func (tx *DecryptionKeyTx) gasPrice() *big.Int       { return big.NewInt(0) }
func (tx *DecryptionKeyTx) value() *big.Int          { return big.NewInt(0) }
func (tx *DecryptionKeyTx) nonce() uint64            { return 0 }
func (tx *DecryptionKeyTx) to() *common.Address      { return nil }
func (tx *DecryptionKeyTx) encryptedPayload() []byte { return nil }
func (tx *DecryptionKeyTx) decryptionKey() []byte    { return tx.DecryptionKey }

func (tx *DecryptionKeyTx) rawSignatureValues() (v, r, s *big.Int) {
	return big.NewInt(0), big.NewInt(0), big.NewInt(0)
}

func (tx *DecryptionKeyTx) setSignatureValues(chainID, v, r, s *big.Int) {
	// Decryption key transactions are not signed, so do nothing
}
