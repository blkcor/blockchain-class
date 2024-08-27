package signature

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
)

const blkcorID = 27

// Sign signs the data with the given private key.
func Sign(value any, privateKey *ecdsa.PrivateKey) (v, r, s *big.Int, err error) {
	// Prepare the data for signing.
	data, err := stamp(value)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract the bytes for the original public key.
	// TODO: DIFF FROM THE SOURCE CODE
	publicKeyECDSA, err := crypto.SigToPub(data, sig)
	if err != nil {
		return nil, nil, nil, errors.New("error while extracting public key")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	// Check the public key validates the data and signature.
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(publicKeyBytes, data, rs) {
		return nil, nil, nil, errors.New("invalid signature produced")
	}

	// Convert the 65 byte signature into the [R|S|V] format.
	v, r, s = toSignatureValues(sig)

	return v, r, s, nil
}

// toSignatureValues converts the 65 byte signature into the [V|R|S] format.
func toSignatureValues(sig []byte) (v, r, s *big.Int) {
	// The signature is in the [R|S|V] format.
	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64] + blkcorID})

	return v, r, s
}

// stamp returns a hash of 32 bytes that represents this data with
// the blkcor stamp embedded into the final hash.
func stamp(value any) ([]byte, error) {

	// Marshal the data.
	v, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// This stamp is used so signatures we produce when signing data
	// are always unique to the blkcor blockchain.
	stamp := []byte(fmt.Sprintf("\x19Blkcor Signed Message:\n%d", len(v)))

	// Hash the stamp and txHash together in a final 32 byte array
	// that represents the data.
	data := crypto.Keccak256(stamp, v)

	return data, nil
}
