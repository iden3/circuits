package utils

import (
	"bytes"
	"encoding/hex"
	json "encoding/json"
	"fmt"
	"math/big"
	"os"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"test/crypto/primitive"
)

func ExtractPubXY(privKHex string) (key *babyjub.PrivateKey, x, y *big.Int) {
	// Extract pubKey
	var k babyjub.PrivateKey
	if _, err := hex.Decode(k[:], []byte(privKHex)); err != nil {
		panic(err)
	}
	pk := k.Public()
	return &k, pk.X, pk.Y
}

func ExitOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func AuthClaimFromPubKey(X, Y *big.Int) (*core.Claim, error) {
	var schemaHash core.SchemaHash
	schemaEncodedBytes, _ := hex.DecodeString("ca938857241db9451ea329256b9c06e5")
	copy(schemaHash[:], schemaEncodedBytes)

	// NOTE: We take nonce as hash of public key to make it random
	// We don't use random number here because this test vectors will be used for tests
	// and have randomization inside tests is usually a bad idea
	revNonce, err := poseidon.Hash([]*big.Int{X})
	ExitOnError(err)

	return core.NewClaim(schemaHash,
		core.WithIndexDataInts(X, Y),
		core.WithRevocationNonce(revNonce.Uint64()))
}

func SignBBJJ(key *babyjub.PrivateKey, sigInput []byte) (*babyjub.Signature, error) {
	bjjSigner := primitive.NewBJJSigner(key)
	signature, err := bjjSigner.Sign(sigInput)
	ExitOnError(err)

	var sig [64]byte
	copy(sig[:], signature)

	return new(babyjub.Signature).Decompress(sig)
}

func PrintMap(inputs map[string]interface{}) {
	b, err := MarshalIndent(inputs, "", "  ")
	ExitOnError(err)

	fmt.Println(string(b))
}

func PrintSiblings(name string, siblings []*merkletree.Hash) {
	b, err := json.Marshal(siblings)
	if err != nil {
		panic(err)
	}
	fmt.Println(name, string(b))
}

func PadSiblingsToTreeLevels(siblings []*merkletree.Hash, treeLevels int) []*merkletree.Hash {
	s := make([]*merkletree.Hash, treeLevels)
	zero, _ := merkletree.NewHashFromString("0")
	if treeLevels > len(siblings) {
		for i := 0; i < len(siblings); i++ {
			s[i] = siblings[i]
		}
		for i := len(siblings); i < treeLevels; i++ {
			s[i] = zero
		}
	} else {
		for i := 0; i < treeLevels; i++ {
			s[i] = siblings[i]
		}
	}

	return s
}

func ClaimToString(claim *core.Claim) string {
	b, err := json.Marshal(claim)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = Indent(&buf, b, prefix, indent)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// this is a modified copy from the json package of stdlib
// it does not print newlines after each item in an array
// this is to make the output more readable and with much less vertical size
func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error {
	needIndent := false
	needNewLine := true
	depth := 0
	for _, c := range src {

		// Add spacing around real punctuation.
		switch c {
		case '{':
			// delay indent so that empty object and array are formatted as {} and [].
			needIndent = true
			dst.WriteByte(c)
		case '[':
			needNewLine = false
			dst.WriteByte(c)
		case ',':
			dst.WriteByte(c)
			if needNewLine {
				newline(dst, prefix, indent, depth)
			}

		case ':':
			dst.WriteByte(c)
			dst.WriteByte(' ')

		case '}':
			if needIndent {
				// suppress indent in empty object/array
				needIndent = false
			} else {
				depth--
				newline(dst, prefix, indent, depth)
			}
			dst.WriteByte(c)
		case ']':
			needNewLine = true
			dst.WriteByte(c)
		default:
			dst.WriteByte(c)
		}
	}
	return nil
}

func newline(dst *bytes.Buffer, prefix, indent string, depth int) {
	dst.WriteByte('\n')
	dst.WriteString(prefix)
	for i := 0; i < depth; i++ {
		dst.WriteString(indent)
	}
}
