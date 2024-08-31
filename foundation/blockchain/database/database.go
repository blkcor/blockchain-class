// Package database handles all the lower level support for maintaining the blockchain database.
package database

import (
	"errors"
	"github.com/ardanlabs/blockchain/foundation/blockchain/genesis"
	"sync"
)

// Database manages the data related to the accounts who have transacted on the blockchain.
type Database struct {
	mu      sync.RWMutex
	genesis genesis.Genesis
	//latestBlock Block
	accounts map[AccountID]Account
	//storage     Storage
}

// New constructs a new Database value with the provided genesis block and event handler.
func New(genesis genesis.Genesis, evHandler func(v string, args ...any)) (*Database, error) {
	db := Database{
		genesis:  genesis,
		accounts: make(map[AccountID]Account),
	}
	for accountStr, balance := range genesis.Balances {
		accountID, err := ToAccountID(accountStr)
		if err != nil {
			return nil, err
		}
		db.accounts[accountID] = newAccount(accountID, balance)
	}
	return &db, nil
}

// Remove removes the account from the database.
func (db *Database) Remove(accountID AccountID) {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.accounts, accountID)
}

// Query retrieves the account from the database.
func (db *Database) Query(accountID AccountID) (Account, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	account, ok := db.accounts[accountID]
	if !ok {
		return Account{}, errors.New("account doesn't exist")
	}
	return account, nil
}

// Copy make a copy of current accounts in the database.
func (db *Database) Copy() map[AccountID]Account {
	db.mu.RLock()
	defer db.mu.RUnlock()

	accounts := make(map[AccountID]Account)
	for accountID, account := range db.accounts {
		accounts[accountID] = account
	}
	return accounts
}
