package signature

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
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

// VerifySignature validates the signature of the data.
func VerifySignature(v *big.Int, r *big.Int, s *big.Int) error {
	// Check the recovery id is 0 or 1.
	intV := v.Int64() - blkcorID
	if intV != 0 && intV != 1 {
		return errors.New("invalid recovery id")
	}

	// Check if the signature is valid.
	if !crypto.ValidateSignatureValues(byte(intV), r, s, false) {
		return errors.New("invalid signature")
	}
	return nil
}

// FromAddress extract the address from the signature.
func FromAddress(value any, v, r, s *big.Int) (string, error) {
	// prepare data
	data, err := stamp(value)
	if err != nil {
		return "", err
	}

	// convert [R|S|V] to 65 byte signature
	sig := ToSignatureBytes(v, r, s)
	// capture the public key associate with the data and the signature
	pk, err := crypto.SigToPub(data, sig)
	if err != nil {
		return "", err
	}

	return crypto.PubkeyToAddress(*pk).Hex(), nil
}

// ToSignatureBytes converts the [V|R|S] signature into a 65 byte signature.
func ToSignatureBytes(v, r, s *big.Int) []byte {
	sig := make([]byte, crypto.SignatureLength)

	rBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	copy(sig, rBytes)

	sBytes := make([]byte, 32)
	s.FillBytes(sBytes)
	copy(sig[32:], sBytes)

	sig[64] = byte(v.Uint64() - blkcorID)
	return sig
}

// ToSignatureBytesWithBlkcorID converts the [V|R|S] signature into a 65 byte signature with adding the blkcorID.
func ToSignatureBytesWithBlkcorID(v, r, s *big.Int) []byte {
	sig := ToSignatureBytes(v, r, s)
	sig[64] = byte(v.Uint64())
	return sig
}

// SigString returns the signature as a hex encoded string.
func SigString(v, r, s *big.Int) string {
	return hexutil.Encode(ToSignatureBytesWithBlkcorID(v, r, s))
}
