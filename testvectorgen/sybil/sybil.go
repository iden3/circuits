package sybil

import (
	"context"
	"encoding/json"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/stretchr/testify/require"
	"math/big"
	"test/utils"
	"testing"
)

func generateTestDataMTP(t *testing.T, desc, fileName string) {
	var err error

	user := utils.NewIdentity(t, mtpUserPK)
	issuer := utils.NewIdentity(t, mtpIssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	//if isUserIDProfile {
	//	nonce = big.NewInt(10)
	//	userProfileID, err = core.ProfileID(user.ID, nonce)
	//	require.NoError(t, err)
	//}

	subjectID := user.ID
	//nonceSubject := big.NewInt(0)
	//if isSubjectIDProfile {
	//	nonceSubject = big.NewInt(999)
	//	subjectID, err = core.ProfileID(user.ID, nonceSubject)
	//	require.NoError(t, err)
	//}

	// unique claim
	uniClaim := utils.DefaultUserClaim(t, subjectID)
	issuer.AddClaim(t, uniClaim)
	issuerClaimMtp, _ := issuer.ClaimMTP(t, uniClaim)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, uniClaim)

	secret := big.NewInt(10)
	ssClaim := utils.UserStateSecretClaim(t, secret)
	user.AddClaim(t, ssClaim)
	userClaimMtp, _ := user.ClaimMTP(t, ssClaim)

	// gist
	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	require.Nil(t, err)
	gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))

	err = gisTree.Add(context.Background(), user.IDHash(t), user.State(t))
	require.Nil(t, err)

	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := InputsMTP{
		IssuerClaim:           uniClaim,
		IssuerClaimMtp:        issuerClaimMtp,
		IssuerClaimClaimsRoot: issuer.Clt.Root(),
		IssuerClaimRevRoot:    issuer.Ret.Root(),
		IssuerClaimRootsRoot:  issuer.Rot.Root(),
		IssuerClaimIdenState:  issuer.State(t).String(),

		IssuerClaimNonRevMtp:      issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi: issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv: issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux: issuerClaimNonRevAux.NoAux,

		IssuerClaimNonRevClaimsRoot: issuer.Clt.Root(),
		IssuerClaimNonRevRevRoot:    issuer.Ret.Root(),
		IssuerClaimNonRevRootsRoot:  issuer.Rot.Root(),
		IssuerClaimNonRevState:      issuer.State(t).String(),

		HolderClaim:           ssClaim,
		HolderClaimMtp:        userClaimMtp,
		HolderClaimClaimsRoot: user.Clt.Root(),
		HolderClaimRevRoot:    user.Ret.Root(),
		HolderClaimRootsRoot:  user.Rot.Root(),
		HolderClaimIdenState:  user.State(t).String(),

		GistRoot:     gistRoot,
		GistMtp:      gistProof,
		GistMtpAuxHi: gistNodAux.Key,
		GistMtpAuxHv: gistNodAux.Value,
		GistMtpNoAux: gistNodAux.NoAux,

		CRS: big.NewInt(123456789).String(),

		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),
	}

	out := Outputs{
		UserID:  userProfileID.BigInt().String(),
		SybilID: "20862964869267347971331838950951441214503092363786002222571056178548832852731",
	}

	jsonTestData, err := json.Marshal(TestDataMTP{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonTestData))
}

func generateTestDataSig(t *testing.T, desc, fileName string) {
	user := utils.NewIdentity(t, mtpUserPK)
	issuer := utils.NewIdentity(t, mtpIssuerPK)

	userProfileID := user.ID
	nonce := big.NewInt(0)
	//if isUserIDProfile {
	//	nonce = big.NewInt(10)
	//	userProfileID, err = core.ProfileID(user.ID, nonce)
	//	require.NoError(t, err)
	//}

	subjectID := user.ID
	//nonceSubject := big.NewInt(0)
	//if isSubjectIDProfile {
	//	nonceSubject = big.NewInt(999)
	//	subjectID, err = core.ProfileID(user.ID, nonceSubject)
	//	require.NoError(t, err)
	//}

	// Sig claim
	claim := utils.DefaultUserClaim(t, subjectID)
	claimSig := issuer.SignClaim(t, claim)
	issuerClaimNonRevState := issuer.State(t)
	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)
	issuerAuthClaimMtp, issuerAuthClaimNodeAux := issuer.ClaimRevMTP(t, issuer.AuthClaim)

	secret := big.NewInt(10)
	ssClaim := utils.UserStateSecretClaim(t, secret)
	user.AddClaim(t, ssClaim)
	userClaimMtp, _ := user.ClaimMTP(t, ssClaim)

	// gist
	gisTree, err := merkletree.NewMerkleTree(context.Background(), memory.NewMemoryStorage(), 32)
	require.Nil(t, err)
	gisTree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	err = gisTree.Add(context.Background(), user.IDHash(t), user.State(t))
	require.Nil(t, err)
	gistProofRaw, _, err := gisTree.GenerateProof(context.Background(), user.IDHash(t), nil)
	gistRoot := gisTree.Root()
	gistProof, gistNodAux := utils.PrepareProof(gistProofRaw)

	inputs := InputsSig{
		IssuerClaim:                   claim,
		IssuerClaimNonRevClaimsRoot:   issuer.Clt.Root().BigInt().String(),
		IssuerClaimNonRevRevRoot:      issuer.Ret.Root().BigInt().String(),
		IssuerClaimNonRevRootsRoot:    issuer.Rot.Root().BigInt().String(),
		IssuerClaimNonRevState:        issuerClaimNonRevState.String(),
		IssuerClaimNonRevMtp:          issuerClaimNonRevMtp,
		IssuerClaimNonRevMtpAuxHi:     issuerClaimNonRevAux.Key,
		IssuerClaimNonRevMtpAuxHv:     issuerClaimNonRevAux.Value,
		IssuerClaimNonRevMtpNoAux:     issuerClaimNonRevAux.NoAux,
		IssuerClaimSignatureR8X:       claimSig.R8.X.String(),
		IssuerClaimSignatureR8Y:       claimSig.R8.Y.String(),
		IssuerClaimSignatureS:         claimSig.S.String(),
		IssuerAuthClaim:               issuer.AuthClaim,
		IssuerAuthClaimMtp:            issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtp:      issuerAuthClaimMtp,
		IssuerAuthClaimNonRevMtpAuxHi: issuerAuthClaimNodeAux.Key,
		IssuerAuthClaimNonRevMtpAuxHv: issuerAuthClaimNodeAux.Value,
		IssuerAuthClaimNonRevMtpNoAux: issuerAuthClaimNodeAux.NoAux,
		IssuerAuthClaimsRoot:          issuer.Clt.Root().BigInt().String(),
		IssuerAuthRevRoot:             issuer.Ret.Root().BigInt().String(),
		IssuerAuthRootsRoot:           issuer.Rot.Root().BigInt().String(),

		HolderClaim:           ssClaim,
		HolderClaimMtp:        userClaimMtp,
		HolderClaimClaimsRoot: user.Clt.Root(),
		HolderClaimRevRoot:    user.Ret.Root(),
		HolderClaimRootsRoot:  user.Rot.Root(),
		HolderClaimIdenState:  user.State(t).String(),

		GistRoot:     gistRoot,
		GistMtp:      gistProof,
		GistMtpAuxHi: gistNodAux.Key,
		GistMtpAuxHv: gistNodAux.Value,
		GistMtpNoAux: gistNodAux.NoAux,

		CRS: big.NewInt(123456789).String(),

		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),
	}

	out := Outputs{
		UserID:  userProfileID.BigInt().String(),
		SybilID: "20862964869267347971331838950951441214503092363786002222571056178548832852731",
	}

	jsonTestData, err := json.Marshal(TestDataSig{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonTestData))
}
