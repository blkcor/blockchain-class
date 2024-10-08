package database

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/ardanlabs/blockchain/foundation/blockchain/signature"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"math/big"
	"time"
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

// Validate checks if the transaction is valid.
func (tx SignedTx) Validate(chainID uint16) error {
	if chainID != tx.ChainID {
		return fmt.Errorf("invalid chainID expect [%d], get [%d]", chainID, tx.ChainID)
	}
	if !tx.FromID.IsAccountID() {
		return errors.New("invalid from account ID")
	}
	if !tx.ToID.IsAccountID() {
		return errors.New("invalid to account ID")
	}
	if tx.FromID == tx.ToID {
		return errors.New("you could not transfer to yourself")
	}
	if err := signature.VerifySignature(tx.V, tx.R, tx.S); err != nil {
		return err
	}
	address, err := signature.FromAddress(tx.Data, tx.V, tx.R, tx.S)
	if err != nil {
		return err
	}
	// Check if the from address is the same as the address derived from the signature.
	if address != string(tx.FromID) {
		return errors.New("signature address is not match the from address")
	}
	return nil
}

// SignatureString returns the signature string.
func (tx SignedTx) SignatureString() string {
	return signature.SigString(tx.V, tx.R, tx.S)
}

// String returns the string representation of the transaction.
func (tx Tx) String() string {
	return fmt.Sprintf("%s:%d", tx.FromID, tx.Nonce)
}

// BlockTx represents a transaction in a block that actually
// will be blocked into the blockchain.
type BlockTx struct {
	SignedTx
	TimeStamp uint64 `json:"timestamp"`
	GasPrice  uint64 `json:"gas_price"`
	GasUnit   uint64 `json:"gas_unit"`
}

// NewBlockTx creates a new block transaction with the given parameters.
func NewBlockTx(tx SignedTx, gasPrice, gasUnit uint64) BlockTx {
	return BlockTx{
		SignedTx:  tx,
		TimeStamp: uint64(time.Now().UTC().Unix()),
		GasPrice:  gasPrice,
		GasUnit:   gasUnit,
	}
}

// Hash implement the merkle Hashable interface for providing a hash of the BlockTx.
func (blockTx *BlockTx) Hash() ([]byte, error) {
	hash := signature.Hash(blockTx)
	// remove the 0x prefix
	return hexutil.Decode(hash[2:])
}

// Equal implements the merkle Hashable interface for providing the equality
// check between two BlockTx.If the nonce and the signature are the same, then
// the two BlockTx are considered equal.
func (blockTx *BlockTx) Equal(other *BlockTx) bool {
	sig1 := signature.ToSignatureBytes(blockTx.V, blockTx.R, blockTx.S)
	sig2 := signature.ToSignatureBytes(other.V, other.R, other.S)

	return blockTx.Nonce == other.Nonce && bytes.Equal(sig1, sig2)
}
