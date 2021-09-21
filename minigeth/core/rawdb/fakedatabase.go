package rawdb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

type KeyValueReader struct {
}

type KeyValueWriter struct {
}

// ReadTrieNode retrieves the trie node of the provided hash.
func ReadTrieNode(db ethdb.KeyValueReader, hash common.Hash) []byte {
	return nil
}

// ReadPreimage retrieves a single preimage of the provided hash.
func ReadPreimage(db ethdb.KeyValueReader, hash common.Hash) []byte {
	/*data, _ := db.Get(preimageKey(hash))
	return data*/
	return nil
}

// WritePreimages writes the provided set of preimages to the database.
func WritePreimages(db ethdb.KeyValueWriter, preimages map[common.Hash][]byte) {
}

// WriteTrieNode writes the provided trie node database.
func WriteTrieNode(db ethdb.KeyValueWriter, hash common.Hash, node []byte) {
	/*if err := db.Put(hash.Bytes(), node); err != nil {
		log.Crit("Failed to store trie node", "err", err)
	}*/
}
