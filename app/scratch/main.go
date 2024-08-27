package main

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
	tx := Tx{
		FromID: "rb",
		ToId:   "ruby",
		Value:  10000,
	}
	// generate a private key from ecdsa file
	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("failed to load ecdsa: %w", err)
	}

	data, err := json.Marshal(tx)
	stamp := []byte(fmt.Sprintf("who sign the data%d", len(data)))
	if err != nil {
		return fmt.Errorf("failed to marshal tx: %w", err)
	}
	data = crypto.Keccak256(stamp, data)

	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign tx: %w", err)
	}

	fmt.Println("Signature: ", hexutil.Encode(sig))

	//calculate the public key
	publicKey, err := crypto.SigToPub(data, sig)
	if err != nil {
		return fmt.Errorf("failed to calculate public key: %w", err)
	}
	pa := crypto.PubkeyToAddress(*publicKey).Hex()
	fmt.Println("Public Address: ", pa)
	return nil
}
