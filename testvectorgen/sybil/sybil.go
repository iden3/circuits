package sybil

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"math/big"
	"test/utils"
	"testing"
)

func generateTestData(t *testing.T, desc, fileName string) {
	var err error

	user := utils.NewIdentity(t, userPK)
	issuer := utils.NewIdentity(t, issuerPK)

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

	uniClaim := utils.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, uniClaim)

	issuerClaimMtp, _ := issuer.ClaimMTP(t, uniClaim)
	require.NoError(t, err)

	issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, uniClaim)

	ssClaim := utils.CreateStateSecretClaim(t, subjectID)

	user.AddClaim(t, ssClaim)

	userClaimMtp, _ := user.ClaimMTP(t, ssClaim)
	require.NoError(t, err)

	//userClaimNonRevMtp, userClaimNonRevAux := user.ClaimRevMTP(t, ssClaim)


	inputs := Inputs{

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

		holderClaim:           ssClaim,
		holderClaimMtp:        userClaimMtp,
		holderClaimClaimsRoot: user.Clt.Root(),
		holderClaimRevRoot:    user.Ret.Root(),
		holderClaimRootsRoot:  user.Rot.Root(),
		holderClaimIdenState:  user.State(t).String(),

		GistRoot:     issuer.Clt.Root(),
		GistMtp:      issuerClaimMtp,
		GistMtpAuxHi: "0",
		GistMtpAuxHv: "0",
		GistMtpNoAux: "0",

		CRS: big.NewInt(123456789).String(),

		UserGenesisID: user.ID.BigInt().String(),
		ProfileNonce:  nonce.String(),
		//ClaimSubjectProfileNonce:        nonceSubject.String()
	}

	out := Outputs{
		UserID:  userProfileID.BigInt().String(),
		SybilID: issuer.ID.BigInt().String(),
	}

	jsonTestData, err := json.Marshal(TestDataMTPV2{
		desc,
		inputs,
		out,
	})
	require.NoError(t, err)

	utils.SaveTestVector(t, fileName, string(jsonTestData))
}
