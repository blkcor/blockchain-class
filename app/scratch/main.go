package main

import (
	"errors"
	"fmt"
	"github.com/ardanlabs/blockchain/foundation/blockchain/database"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

type Tx struct {
	FromID string `json:"from_id"`
	ToId   string `json:"to_id"`
	Value  uint64 `json:"value"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	// generate a private key from ecdsa file
	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return errors.New("failed to load private key, err: " + err.Error())
	}

	tx, err := database.NewTx(1, 1,
		"0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		"0xdd6B972ffcc631a62CAE1BB9d80b7ff429c8ebA4",
		10000,
		0,
		nil)
	if err != nil {
		return errors.New("failed to create tx, err: " + err.Error())
	}

	// sign the transaction
	signedTx, err := tx.Sign(privateKey)
	if err != nil {
		return errors.New("failed to sign tx, err: " + err.Error())
	}
	fmt.Println("signed tx: ", signedTx)
	return nil
}
