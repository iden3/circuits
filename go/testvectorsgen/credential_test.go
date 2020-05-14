package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/iden3/go-circom-prover-verifier/parsers"
	zktypes "github.com/iden3/go-circom-prover-verifier/types"
	"github.com/iden3/go-iden3-core/components/idenpuboffchain"
	idenpuboffchanlocal "github.com/iden3/go-iden3-core/components/idenpuboffchain/local"
	"github.com/iden3/go-iden3-core/components/idenpubonchain"
	idenpubonchainlocal "github.com/iden3/go-iden3-core/components/idenpubonchain/local"
	"github.com/iden3/go-iden3-core/core/claims"
	"github.com/iden3/go-iden3-core/db"
	"github.com/iden3/go-iden3-core/identity/holder"
	"github.com/iden3/go-iden3-core/identity/issuer"
	"github.com/iden3/go-iden3-core/keystore"
	"github.com/iden3/go-iden3-core/merkletree"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	log "github.com/sirupsen/logrus"
)

var blockN uint64
var blockTs int64

var idenPubOffChain *idenpuboffchanlocal.IdenPubOffChain
var idenPubOnChain *idenpubonchainlocal.IdenPubOnChain
var idenStateZkProofConf *issuer.IdenStateZkProofConf

var pass = []byte("my passphrase")

const idOwnershipLevels = 4
const issuerLevels = 8

func newIssuer(t *testing.T, idenPubOnChain idenpubonchain.IdenPubOnChainer,
	idenPubOffChainWrite idenpuboffchain.IdenPubOffChainWriter) (*issuer.Issuer, db.Storage, *keystore.KeyStore) {
	cfg := issuer.ConfigDefault
	storage := db.NewMemoryStorage()
	ksStorage := keystore.MemStorage([]byte{})
	keyStore, err := keystore.NewKeyStore(&ksStorage, keystore.LightKeyStoreParams)
	require.Nil(t, err)
	// kOp, err := keyStore.NewKey(pass)
	var sk babyjub.PrivateKey
	sk[0] = 0x11
	kOp, err := keyStore.ImportKey(sk, pass)
	require.Nil(t, err)
	err = keyStore.UnlockKey(kOp, pass)
	require.Nil(t, err)
	_, err = issuer.Create(cfg, kOp, []claims.Claimer{}, storage, keyStore)
	require.Nil(t, err)
	is, err := issuer.Load(storage, keyStore, idenPubOnChain, idenStateZkProofConf, idenPubOffChainWrite)
	require.Nil(t, err)
	return is, storage, keyStore
}

func newHolder(t *testing.T, idenPubOnChain idenpubonchain.IdenPubOnChainer,
	idenPubOffChainWrite idenpuboffchain.IdenPubOffChainWriter,
	idenPubOffChainRead idenpuboffchain.IdenPubOffChainReader) (*holder.Holder, db.Storage, *keystore.KeyStore) {
	cfg := holder.ConfigDefault
	storage := db.NewMemoryStorage()
	ksStorage := keystore.MemStorage([]byte{})
	keyStore, err := keystore.NewKeyStore(&ksStorage, keystore.LightKeyStoreParams)
	require.Nil(t, err)
	// kOp, err := keyStore.NewKey(pass)
	var sk babyjub.PrivateKey
	sk[0] = 0x22
	kOp, err := keyStore.ImportKey(sk, pass)
	require.Nil(t, err)
	err = keyStore.UnlockKey(kOp, pass)
	require.Nil(t, err)
	_, err = holder.Create(cfg, kOp, []claims.Claimer{}, storage, keyStore)
	require.Nil(t, err)
	ho, err := holder.Load(storage, keyStore, idenPubOnChain, idenStateZkProofConf,
		idenPubOffChainWrite, idenPubOffChainRead)
	require.Nil(t, err)
	return ho, storage, keyStore
}

func TestVerifyCredentialValidity(t *testing.T) {

	ho, _, _ := newHolder(t, idenPubOnChain, nil, idenPubOffChain)

	//
	// {Ts: 1000, BlockN: 120} -> claim1 is added
	//
	blockTs, blockN = 1000, 120

	// ISSUER: Publish state first time with claim1

	indexBytes, valueBytes := [claims.IndexSubjectSlotLen]byte{}, [claims.ValueSlotLen]byte{}
	indexBytes[0] = 0x42
	valueBytes[0] = 0x43
	claim1 := claims.NewClaimOtherIden(ho.ID(), indexBytes, valueBytes)

	is, _, _ := newIssuer(t, idenPubOnChain, idenPubOffChain)
	err := is.IssueClaim(claim1)
	require.Nil(t, err)

	// Publishing state for the first time
	err = is.PublishState()
	require.Nil(t, err)
	idenPubOnChain.Sync()

	blockTs += 20
	blockN += 10

	err = is.SyncIdenStatePublic()
	require.Nil(t, err)

	credExistClaim1, err := is.GenCredentialExistence(claim1)
	require.Nil(t, err)

	// HOLDER + VERIFIER

	// credValidClaim1t1, err := ho.HolderGetCredentialValidity(credExistClaim1)
	// require.Nil(t, err)

	//
	// {Ts: 2000, BlockN: 130} -> claim2 is added
	//
	blockTs, blockN = 2000, 130

	// ISSUER: Publish state a second time with another claim2, claim3

	indexBytes, valueBytes = [claims.IndexSubjectSlotLen]byte{}, [claims.ValueSlotLen]byte{}
	indexBytes[0] = 0x48
	valueBytes[0] = 0x49
	claim2 := claims.NewClaimOtherIden(ho.ID(), indexBytes, valueBytes)

	err = is.IssueClaim(claim2)
	require.Nil(t, err)

	// claim3 is a claim with expiration at T=3500

	header := claims.ClaimHeader{
		Type:       claims.NewClaimTypeNum(9999),
		Subject:    claims.ClaimSubjectSelf,
		Expiration: true,
		Version:    false,
	}
	metadata := claims.NewMetadata(header)
	metadata.Expiration = 3500
	var entry merkletree.Entry
	metadata.Marshal(&entry)
	claim3 := claims.NewClaimGeneric(&entry)

	err = is.IssueClaim(claim3)
	require.Nil(t, err)

	err = is.PublishState()
	require.Nil(t, err)
	idenPubOnChain.Sync()

	blockTs += 20
	blockN += 10

	err = is.SyncIdenStatePublic()
	require.Nil(t, err)

	// credExistClaim2, err := is.GenCredentialExistence(claim2)
	// require.Nil(t, err)

	// HOLDER + VERIFIER

	credValid, err := ho.HolderGetCredentialValidity(credExistClaim1)
	assert.Nil(t, err)
	assert.NotNil(t, credValid)

	idOwnershipInputs, err := ho.GenIdOwnershipGenesisInputs(idOwnershipLevels)
	assert.Nil(t, err)
	credProofInputs, err := ho.HolderGetCredentialProofInputs(idOwnershipInputs,
		credExistClaim1, issuerLevels)
	assert.Nil(t, err)
	assert.NotNil(t, credProofInputs)

	credProofInputsString, err := InputToStrings(credProofInputs)
	assert.Nil(t, err)
	credProofInputsStringJSON, err := json.MarshalIndent(credProofInputsString, "", "  ")
	assert.Nil(t, err)
	fmt.Printf("const inputs1JSON = `\n%v\n`;\n", string(credProofInputsStringJSON))

	// Add some random claims
	for i := 0; i < 4; i++ {
		indexBytes, valueBytes := [claims.IndexSlotLen]byte{}, [claims.ValueSlotLen]byte{}
		indexBytes[0] = 0x10 + byte(i)
		claim := claims.NewClaimBasic(indexBytes, valueBytes)
		err = is.IssueClaim(claim)
		require.Nil(t, err)
	}

	indexBytes, valueBytes = [claims.IndexSubjectSlotLen]byte{}, [claims.ValueSlotLen]byte{}
	indexBytes[0] = 0x52
	valueBytes[0] = 0x53
	claim4 := claims.NewClaimOtherIden(ho.ID(), indexBytes, valueBytes)
	err = is.IssueClaim(claim4)
	require.Nil(t, err)

	err = is.RevokeClaim(claim1)
	require.Nil(t, err)
	// err = is.RevokeClaim(claim3)
	// require.Nil(t, err)

	// Publishing state for the first time
	err = is.PublishState()
	require.Nil(t, err)
	idenPubOnChain.Sync()

	blockTs += 20
	blockN += 10

	err = is.SyncIdenStatePublic()
	require.Nil(t, err)

	credExistClaim4, err := is.GenCredentialExistence(claim4)
	require.Nil(t, err)

	credProofInputs, err = ho.HolderGetCredentialProofInputs(idOwnershipInputs,
		credExistClaim4, issuerLevels)
	assert.Nil(t, err)
	assert.NotNil(t, credProofInputs)

	credProofInputsString, err = InputToStrings(credProofInputs)
	assert.Nil(t, err)
	credProofInputsStringJSON, err = json.MarshalIndent(credProofInputsString, "", "  ")
	assert.Nil(t, err)
	fmt.Printf("const inputs2JSON = `\n%v\n`;\n", string(credProofInputsStringJSON))
}

func InputToStrings(input interface{}) (interface{}, error) {
	var inputMap map[string]interface{}
	if err := mapstructure.Decode(input, &inputMap); err != nil {
		return nil, err
	}
	inputStrings := make(map[string]interface{})
	for key, value := range inputMap {
		switch v := value.(type) {
		case *big.Int:
			inputStrings[key] = v.String()
		case []*big.Int:
			vs := make([]string, len(v))
			for i, v := range v {
				vs[i] = v.String()
			}
			inputStrings[key] = vs
		default:
			panic(fmt.Sprintf("Type: %T", value))
		}
	}
	return inputStrings, nil
}

var _vk *zktypes.Vk

func TestMain(m *testing.M) {
	log.SetLevel(log.DebugLevel)
	downloadPath := "/tmp/iden3/idenstatezk"
	err := issuer.GetIdenStateZKFiles("http://161.35.72.58:9000/circuit-idstate/", downloadPath)
	if err != nil {
		panic(err)
	}
	vkJSON, err := ioutil.ReadFile(path.Join(downloadPath, "verification_key.json"))
	if err != nil {
		panic(err)
	}
	vk, err := parsers.ParseVk(vkJSON)
	if err != nil {
		panic(err)
	}
	_vk = vk
	idenPubOnChain = idenpubonchainlocal.New(
		func() time.Time {
			return time.Unix(blockTs, 0)
		},
		func() uint64 {
			return blockN
		},
		vk,
	)
	idenPubOffChain = idenpuboffchanlocal.NewIdenPubOffChain("http://foo.bar")
	idenStateZkProofConf = &issuer.IdenStateZkProofConf{
		Levels:              16,
		PathWitnessCalcWASM: path.Join(downloadPath, "circuit.wasm"),
		PathProvingKey:      path.Join(downloadPath, "proving_key.json"),
		PathVerifyingKey:    path.Join(downloadPath, "verification_key.json"),
		CacheProvingKey:     true,
	}
	os.Exit(m.Run())
}
