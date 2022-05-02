package main

import (
	"context"
	"encoding/hex"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"math/big"
	"test/utils"

	"test/crypto/primitive"
)

func main() {
	fmt.Println("\n-------\nNew identity test vectors:")

	privKeysHex := []string{
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f",
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69e",
		"28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69d",
	}

	treeLevels := 4

	numberOfKeys := 1
	numberOfFirstClaimsToRevoke := 0
	signingKeyIndex := 0

	useRelay := false

	//todo If useOldAndNewStateForChallenge = true then an input for stateTransition circuit is generated
	// It has correct values but wrong names, which is something that is better to fix
	useOldAndNewStateForChallenge := false
	newState, _ := big.NewInt(0).SetString("8061408109549794622894897529509400209321866093562736009325703847306244896707", 10)

	//claimSchema, _ := big.NewInt(0).SetString("251025091000101825075425831481271126140", 10)

	fmt.Println("Number of keys:", numberOfKeys)
	fmt.Println("Signing key index:", signingKeyIndex)
	fmt.Println("Number of first keys to revoke:", numberOfFirstClaimsToRevoke)
	fmt.Println("Use relay:", useRelay)

	privKeys := createPrivateKeys(privKeysHex[:numberOfKeys])
	authClaims := createAuthClaims(privKeys)

	for i, v := range privKeys {
		isSigningKey := false
		isRevokedKey := false
		if i == signingKeyIndex {
			isSigningKey = true
		}
		if i < numberOfFirstClaimsToRevoke {
			isRevokedKey = true
		}

		hIndex, hValue, err := authClaims[i].HiHv()
		utils.ExitOnError(err)

		fmt.Println()
		fmt.Println("Claim info: ")
		fmt.Println(fmt.Sprintf("    Public key: %v, isSigningKey: %t, isRevokedKey: %t", i, isSigningKey, isRevokedKey))
		fmt.Println("    HIndex: ", hIndex.String())
		fmt.Println("    HValue: ", hValue.String())
		//fmt.Println("    Schema: ", claimSchema)
		fmt.Println("    x", v.Public().X)
		fmt.Println("    y", v.Public().Y)
		fmt.Println("    Revocation nonce: ", authClaims[i].GetRevocationNonce())
		//schema, err := authClaims[signingKeyIndex].GetSchemaHash().MarshalText()
		//fmt.Println("    GetSchemaHash: ", big.NewInt(0).SetBytes(schema))
	}

	testVector := make(map[string]string)

	ctx := context.Background()
	identifier, claimsTree, revTree, userState := createIdentityMultiAuthClaims(ctx, authClaims, numberOfFirstClaimsToRevoke, treeLevels)

	if useRelay {
		testVector["userID"] = identifier.BigInt().String()
	} else {
		testVector["userState"] = userState.BigInt().String()
	}
	//MTP Claim
	testVector["userClaimsTreeRoot"] = claimsTree.Root().BigInt().String()
	signingAuthClaim := authClaims[signingKeyIndex]
	hIndex, _, err := signingAuthClaim.HiHv()
	utils.ExitOnError(err)
	proof, _, err := claimsTree.GenerateProof(ctx, hIndex, claimsTree.Root())
	utils.ExitOnError(err)
	allSiblingsClaimsTree := proof.AllSiblings()
	testVector["userAuthClaimMtp"] = utils.SiblingsToString(allSiblingsClaimsTree, treeLevels)
	testVector["userAuthClaim"] = utils.ClaimToString(signingAuthClaim)

	//MTP Claim not revoked
	revNonce := signingAuthClaim.GetRevocationNonce()
	hi := new(big.Int).SetUint64(revNonce)
	proofNotRevoke, _, err := revTree.GenerateProof(ctx, hi, revTree.Root())
	utils.ExitOnError(err)

	testVector["userRevTreeRoot"] = revTree.Root().BigInt().String()
	testVector["userAuthClaimNonRevMtp"] = utils.SiblingsToString(proofNotRevoke.AllSiblings(), treeLevels)
	if proofNotRevoke.NodeAux == nil {
		testVector["userAuthClaimNonRevMtpNoAux"] = "1"
		testVector["userAuthClaimNonRevMtpAuxHi"] = "0"
		testVector["userAuthClaimNonRevMtpAuxHv"] = "0"
	} else {
		testVector["userAuthClaimNonRevMtpNoAux"] = "0"
		testVector["userAuthClaimNonRevMtpAuxHi"] = proofNotRevoke.NodeAux.Key.BigInt().String()
		testVector["userAuthClaimNonRevMtpAuxHv"] = proofNotRevoke.NodeAux.Value.BigInt().String()
	}

	testVector["userRootsTreeRoot"] = "0"

	var challenge *big.Int
	// Test signature
	if useOldAndNewStateForChallenge {
		testVector["userID"] = identifier.BigInt().String()
		testVector["oldUserState"] = userState.BigInt().String()
		testVector["newUserState"] = newState.String()
		challenge, _ = poseidon.Hash([]*big.Int{userState.BigInt(), newState})
		delete(testVector, "challenge")
		delete(testVector, "userState")
		if numberOfKeys == 1 {
			testVector["isOldStateGenesis"] = "1"
		} else {
			testVector["isOldStateGenesis"] = "0"
		}
	} else {
		challenge = big.NewInt(1)
		testVector["challenge"] = challenge.String()
	}

	bjjSigner := primitive.NewBJJSigner(&privKeys[signingKeyIndex])
	signature, err := bjjSigner.Sign(challenge.Bytes())
	utils.ExitOnError(err)
	var sig [64]byte
	copy(sig[:], signature)
	var decompressedSig *babyjub.Signature
	decompressedSig, err = new(babyjub.Signature).Decompress(sig)
	utils.ExitOnError(err)

	testVector["challengeSignatureR8x"] = decompressedSig.R8.X.String()
	testVector["challengeSignatureR8y"] = decompressedSig.R8.Y.String()
	testVector["challengeSignatureS"] = decompressedSig.S.String()

	if useRelay {
		idenStateInRelayClaim, reIdenState, relayClaimsTree, proofIdenStateInRelay := utils.GenerateRelayWithIdenStateClaim("9db637b457c284e844e58955c54cd8e67d989b72ed4b56411eabbeb775fb853a", identifier, userState)

		testVector["relayState"] = reIdenState.BigInt().String()
		testVector["userStateInRelayClaimMtp"] = utils.SiblingsToString(proofIdenStateInRelay.AllSiblings(), treeLevels)
		testVector["userStateInRelayClaim"] = utils.ClaimToString(idenStateInRelayClaim)
		testVector["relayProofValiduserClaimsTreeRoot"] = relayClaimsTree.BigInt().String()
		testVector["relayProofValiduserRevTreeRoot"] = "0"
		testVector["relayProofValiduserRootsTreeRoot"] = "0"
	}

	fmt.Println()
	utils.PrintMap(testVector)
}

func createIdentityMultiAuthClaims(ctx context.Context, authClaims []*core.Claim, numOfFirstClaimsToRevoke int, treeLevels int) (*core.ID, *merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.Hash) {
	claimTreeStorage := memory.NewMemoryStorage()
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimTreeStorage, treeLevels)
	utils.ExitOnError(err)

	var identifier *core.ID

	for i, claim := range authClaims {
		hi, hv, err := claim.HiHv()
		utils.ExitOnError(err)
		err = claimsTree.Add(ctx, hi, hv)
		utils.ExitOnError(err)
		if i == 0 {
			state, err := core.IdenState(claimsTree.Root().BigInt(), big.NewInt(0), big.NewInt(0))
			utils.ExitOnError(err)
			identifier, err = core.IdGenesisFromIdenState(core.TypeDefault, state)
			utils.ExitOnError(err)
		}
	}

	revTree := createRevTree(ctx, authClaims[:numOfFirstClaimsToRevoke], treeLevels)

	state, err := utils.CalcIdentityStateFromRoots(claimsTree, revTree)
	utils.ExitOnError(err)

	return identifier, claimsTree, revTree, state
}

func createAuthClaims(privKeys []babyjub.PrivateKey) []*core.Claim {
	claims := make([]*core.Claim, len(privKeys))
	for i, v := range privKeys {
		pubKey := v.Public()
		claim, err := utils.AuthClaimFromPubKey(pubKey.X, pubKey.Y)
		utils.ExitOnError(err)
		claims[i] = claim
	}
	return claims
}

func createPrivateKeys(privKeysHex []string) []babyjub.PrivateKey {
	privKeys := make([]babyjub.PrivateKey, len(privKeysHex))
	for i, v := range privKeysHex {
		privKeys[i] = createPrivateKey(v)
	}
	return privKeys
}

func createPrivateKey(privKeyHex string) babyjub.PrivateKey {
	var privKey babyjub.PrivateKey
	if _, err := hex.Decode(privKey[:], []byte(privKeyHex)); err != nil {
		panic(err)
	}
	return privKey
}

func createRevTree(ctx context.Context, authClaims []*core.Claim, treeLevels int) *merkletree.MerkleTree {
	treeStorage := memory.NewMemoryStorage()
	tree, err := merkletree.NewMerkleTree(ctx, treeStorage, treeLevels)
	utils.ExitOnError(err)

	for _, v := range authClaims {
		var err error

		revNonce := v.GetRevocationNonce()

		err = tree.Add(ctx, new(big.Int).SetUint64(revNonce), big.NewInt(0))
		utils.ExitOnError(err)
	}

	return tree
}
