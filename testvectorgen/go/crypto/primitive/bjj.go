package primitive

import (
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/pkg/errors"

	"math/big"
)

// BJJSignatureSize is a size of signature in Bytes
const BJJSignatureSize = 64

var (
	errorNotInitialized         = errors.New("signer is not initialized")
	errorInvalidSignatureLength = errors.New("incorrect signature length")
	errorInvalidPublicKey       = errors.New("invalid bjj public key")
	errorInvalidSignature       = errors.New("invalid signature")
	errorDecompress             = errors.New("can't decompress bjj signature")
)

// BJJSinger represents signer with BJJ key
type BJJSinger struct {
	pk *babyjub.PrivateKey
}

// NewBJJSigner creates new instance oj BJJ signer
func NewBJJSigner(_pk *babyjub.PrivateKey) *BJJSinger {
	return &BJJSinger{pk: _pk}
}

// Sign signs prepared data ( value in field Q)
func (s *BJJSinger) Sign(data []byte) ([]byte, error) {

	if s.pk == nil {
		return nil, errorNotInitialized
	}

	message := big.NewInt(0).SetBytes(data)

	signature := s.pk.SignPoseidon(message)

	compressed := signature.Compress()

	return compressed[:], nil
}

// BJJVerifier represents verifier with BJJ key
type BJJVerifier struct {
}

// Verify verifies BJJ signature on data
func (s *BJJVerifier) Verify(publicKey, data, signature []byte) error {

	if len(signature) != BJJSignatureSize {
		return errorInvalidSignatureLength
	}

	var sig [64]byte
	copy(sig[:], signature)

	decompressed, err := new(babyjub.Signature).Decompress(sig)
	if err != nil {
		return errors.Wrap(err, errorDecompress.Error())
	}

	message := big.NewInt(0).SetBytes(data)

	pub := babyjub.PublicKey{}
	err = pub.UnmarshalText(publicKey)
	if err != nil {
		return errors.Wrap(err, errorInvalidPublicKey.Error())
	}
	valid := pub.VerifyPoseidon(message, decompressed)

	if !valid {
		return errorInvalidSignature
	}
	return nil
}
