package utils

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/processor"
	"math/big"
	"testing"
	"time"
)

func CreateStateSecretClaim(t testing.TB, subject core.ID) *core.Claim {
	secret := big.NewInt(443)

	schemauUrl := "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/stateSecret.json-ld"
	schemaType := "StateSecretCredential"

	//data := []byte(`{ "secret": ` + secret.String() + `, "documentType": 1}`)
	data := []byte(`{ "secret": ` + secret.String() + `}`)

	builder := NewBuilder()
	slots, schemaHash, err := builder.Process(schemauUrl, schemaType, data)
	if err!= nil {
		t.Fatalf("err on builder.process. err: %v", err)
	}
	claimNonce, err := Rand()
	claimReq := &CoreClaimData{
		EncodedSchema:   schemaHash,
		Slots:           *slots,
		SubjectID:       "123",
		Expiration:      12345678888,
		Version:         1,
		Nonce:           &claimNonce,
		SubjectPosition: "SubjectPositionValue",
	}

	c, err := generateCoreClaim(claimReq)
	if err!= nil {
		t.Fatalf("err on generateCoreClaim. err: %v", err)
	}

	return c
}

type CoreClaimData struct {
	EncodedSchema   string
	Slots           processor.ParsedSlots
	SubjectID       string
	Expiration      int64
	Version         uint32
	Nonce           *uint64
	SubjectPosition string
}

func generateCoreClaim(req *CoreClaimData) (*core.Claim, error) {
	var revNonce *uint64
	r, err := Rand()
	if err != nil {
		return nil, err
	}

	revNonce = &r
	if req.Nonce != nil {
		revNonce = req.Nonce
	}

	var coreClaim *core.Claim

	var sh core.SchemaHash
	schemaBytes, err := hex.DecodeString(req.EncodedSchema)
	if err != nil {
		return nil, err
	}
	copy(sh[:], schemaBytes)
	coreClaim, err = core.NewClaim(sh,
		core.WithIndexDataBytes(req.Slots.IndexA, req.Slots.IndexB),
		core.WithValueDataBytes(req.Slots.ValueA, req.Slots.ValueB),
		core.WithRevocationNonce(*revNonce),
		core.WithVersion(req.Version))
	if err != nil {
		return nil, err
	}

	if req.SubjectID != "" {
		var userID core.ID
		userID, err = core.IDFromString(req.SubjectID)
		if err != nil {
			return nil, err
		}

		switch req.SubjectPosition {
		case "", SubjectPositionIndex:
			coreClaim.SetIndexID(userID)
		case SubjectPositionValue:
			coreClaim.SetValueID(userID)
		default:
			return nil, fmt.Errorf("unknown subject position")
		}
	}

	if req.Expiration != 0 {
		coreClaim.SetExpirationDate(time.Unix(req.Expiration, 0))
	}
	return coreClaim, nil
}

func Rand() (uint64, error) {
	var buf [8]byte
	// TODO: this was changed because revocation nonce is cut in dart / js if number is too big
	_, err := rand.Read(buf[:4])

	return binary.LittleEndian.Uint64(buf[:]), err
}

const (
	// SubjectPositionIndex save subject in index part of claim. By default.
	SubjectPositionIndex = "index"
	// SubjectPositionValue save subject in value part of claim.
	SubjectPositionValue = "value"

	BabyJubSignatureType = "BJJSignature2021"
)

