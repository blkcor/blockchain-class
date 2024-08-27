package database

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ardanlabs/blockchain/foundation/blockchain/signature"
	"math/big"
)

// Tx represents a transaction between two accounts.
type Tx struct {
	ChainID uint16    `json:"chain_id"`
	Nonce   uint64    `json:"nonce"`
	FromID  AccountID `json:"from_id"`
	ToID    AccountID `json:"to_id"`
	Value   uint64    `json:"value"`
	Tip     uint64    `json:"tip"`
	Data    []byte    `json:"data"`
}

// NewTx creates a new transaction with the given parameters.
func NewTx(chainID uint16, nonce uint64, fromID, toID AccountID, value, tip uint64, data []byte) (Tx, error) {
	if !fromID.IsAccountID() {
		return Tx{}, errors.New("invalid from account ID")
	}
	if !toID.IsAccountID() {
		return Tx{}, errors.New("invalid to account ID")
	}
	return Tx{
		ChainID: chainID,
		Nonce:   nonce,
		FromID:  fromID,
		ToID:    toID,
		Value:   value,
		Tip:     tip,
		Data:    data,
	}, nil
}

// Sign use the specific private key to sign the transaction.
func (tx Tx) Sign(privateKey *ecdsa.PrivateKey) (SignedTx, error) {
	v, r, s, err := signature.Sign(tx, privateKey)
	if err != nil {
		return SignedTx{}, err
	}
	// Construct the signed transaction by adding the signature
	// in the [R|S|V] format.
	signedTx := SignedTx{
		Tx: tx,
		V:  v,
		R:  r,
		S:  s,
	}
	return signedTx, nil
}

// SignedTx represents a transaction that has been signed by a private key.
type SignedTx struct {
	Tx
	R *big.Int `json:"r"` // 签名中的一部分，256bit(64个16进制位)
	S *big.Int `json:"s"` // 签名中的一部分，256bit，用于确保签名的唯一性和安全性
	V *big.Int `json:"v"` // 可恢复标志为，用来恢复公钥在以太坊中通常取值 27 或 28（以太坊将 0 和 1 加上了 27，以便与其他系统区分）。
}
