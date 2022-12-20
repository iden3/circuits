package sybil

import (
	"encoding/json"
	core "github.com/iden3/go-iden3-core"
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
		nonce = big.NewInt(10)
		userProfileID, err = core.ProfileID(user.ID, nonce)
		require.NoError(t, err)
	//}

	subjectID := user.ID
	//nonceSubject := big.NewInt(0)
	//if isSubjectIDProfile {
	//	nonceSubject = big.NewInt(999)
	//	subjectID, err = core.ProfileID(user.ID, nonceSubject)
	//	require.NoError(t, err)
	//}

	claim := utils.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	//issuerClaimMtp, _ := issuer.ClaimMTP(t, claim)
	//require.NoError(t, err)
	//
	//issuerClaimNonRevMtp, issuerClaimNonRevAux := issuer.ClaimRevMTP(t, claim)

	inputs := Inputs{

		//IssuerClaim:           claim,
		//IssuerClaimMtp:        issuerClaimMtp,
		//IssuerClaimClaimsRoot: issuer.Clt.Root(),
		//IssuerClaimRevRoot:    issuer.Ret.Root(),
		//IssuerClaimRootsRoot:  issuer.Rot.Root(),
		//IssuerClaimIdenState:  issuer.State(t).String(),
		//
		//IssuerClaimNonRevMtp:      issuerClaimNonRevMtp,
		//IssuerClaimNonRevMtpAuxHi: issuerClaimNonRevAux.Key,
		//IssuerClaimNonRevMtpAuxHv: issuerClaimNonRevAux.Value,
		//IssuerClaimNonRevMtpNoAux: issuerClaimNonRevAux.NoAux,
		//
		//IssuerClaimNonRevClaimsRoot: issuer.Clt.Root(),
		//IssuerClaimNonRevRevRoot:    issuer.Ret.Root(),
		//IssuerClaimNonRevRootsRoot:  issuer.Rot.Root(),
		//IssuerClaimNonRevState:      issuer.State(t).String(),
		//
		//IssuerClaimSchema: "",

		//holderClaim:           "",
		//holderClaimMtp:        []string{""},
		//holderClaimClaimsRoot: "",
		//holderClaimRevRoot:    "",
		//holderClaimRootsRoot:  "",
		//holderClaimIdenState:  "",
		//holderClaimSchema:     "",
		//
		//GistRoot:     "",
		//GistMtp:      []string{""},
		//GistMtpAuxHi: "",
		//GistMtpAuxHv: "",
		//GistMtpNoAux: "",
		//
		//CRS: "",

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
