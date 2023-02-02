package onChainZKVerificationExample

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"test/utils"
)

/*
This code generates test vectors for on-chain verification circuit, which is an example
for demonstration purposes. The example is to be used in the relevant ERC proposal.

We aim to do it as simple as possible, so to be clear for any reader outside Iden3 protocol context.
For the same reason, no cryptographic constructions like ClaimsTree or CoreClaim are used here.
An issuer signs a claim, which is just the big.Int array: [userEthereumAddress, userAge]
The circuit will just check the valid signature and if userAge >= UserMinAge
*/

const (
	userPK = "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e"
)

type OnChainZkVerificationExample struct {
	IssuerPubKeyAx             string `json:"issuerPubKeyAx"`
	IssuerPubKeyAy             string `json:"issuerPubKeyAy"`
	IssuerClaimSignatureR8x    string `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8y    string `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS      string `json:"issuerClaimSignatureS"`
	UserEthereumAddressInClaim string `json:"userEthereumAddressInClaim"`
	UserAgeInClaim             string `json:"userAgeInClaim"`
	UserMinAge                 string `json:"userMinAge"`
}

type Claim struct {
	address *big.Int
	age     *big.Int
}

func Test_GenerateTestData(t *testing.T) {
	generateTestData(t)
}

func generateTestData(t *testing.T) {
	addressHexString := "6622b9fFcf797282B86aceF4F688ad1ae5d69Ff3" // reversed bytes of address !!!
	address := big.NewInt(0)
	address.SetString(addressHexString, 16)

	age := big.NewInt(25)
	minAge := big.NewInt(18)

	claim := &Claim{
		address: address,
		age:     age,
	}

	claimHash, err := poseidon.Hash([]*big.Int{claim.address, claim.age})
	if err != nil {
		panic(err)
	}

	key, X, Y := utils.ExtractPubXY(userPK)
	signature := key.SignPoseidon(claimHash)

	inputs := OnChainZkVerificationExample{
		IssuerPubKeyAx:             X.String(),
		IssuerPubKeyAy:             Y.String(),
		IssuerClaimSignatureR8x:    signature.R8.X.String(),
		IssuerClaimSignatureR8y:    signature.R8.Y.String(),
		IssuerClaimSignatureS:      signature.S.String(),
		UserEthereumAddressInClaim: address.String(),
		UserAgeInClaim:             age.String(),
		UserMinAge:                 minAge.String(),
	}
	inputsJson, err := json.Marshal(inputs)
	if err != nil {
		panic(err)
	}

	utils.SaveTestVector(t, "onChainZKVerificationExample", string(inputsJson))
}
