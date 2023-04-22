/*
# idOwnershipBySignature.circom

Circuit to check that the prover is the owner of the identity
- prover is owner of the private key
- prover public key is in a ClaimKeyBBJJ that is inside its Identity State (in Claim tree)
*/

pragma circom 2.1.1;

include "utils/claimUtils.circom";
include "utils/treeUtils.circom";

template IdOwnership(nLevels) {
    signal input userState;

	signal input userClaimsTreeRoot;
	signal input userAuthClaimMtp[nLevels];
	signal input userAuthClaim[8];

	signal input userRevTreeRoot;
    signal input userAuthClaimNonRevMtp[nLevels];
    signal input userAuthClaimNonRevMtpNoAux;
    signal input userAuthClaimNonRevMtpAuxHi;
    signal input userAuthClaimNonRevMtpAuxHv;

	signal input userRootsTreeRoot;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    VerifyAuthClaimAndSignature(nLevels)(
        userClaimsTreeRoot,
        userAuthClaimMtp,
        userAuthClaim,
        userRevTreeRoot,
        userAuthClaimNonRevMtp,
        userAuthClaimNonRevMtpNoAux,
        userAuthClaimNonRevMtpAuxHi,
        userAuthClaimNonRevMtpAuxHv,
        challenge,
        challengeSignatureR8x,
        challengeSignatureR8y,
        challengeSignatureS
    );

    checkIdenStateMatchesRoots()(userClaimsTreeRoot, userRevTreeRoot, userRootsTreeRoot, userState);
}
