pragma circom 2.0.0;

include "authentication.circom";

template VerifyAuthenticationOnChainSmt(IdOwnershipLevels, onChainLevels) {

    signal input userID;
    signal input userState;
    signal input userSalt;
    signal output userNullifier;

    signal input userClaimsTreeRoot;
    signal input userAuthClaimMtp[IdOwnershipLevels];
    signal input userAuthClaim[8];

    signal input userRevTreeRoot;
    signal input userAuthClaimNonRevMtp[IdOwnershipLevels];
    signal input userAuthClaimNonRevMtpNoAux;
    signal input userAuthClaimNonRevMtpAuxHi;
    signal input userAuthClaimNonRevMtpAuxHv;

    signal input userRootsTreeRoot;

    signal input challenge;
    signal input challengeSignatureR8x;
    signal input challengeSignatureR8y;
    signal input challengeSignatureS;

    signal input userStateInOnChainSmtRoot;
    signal input userStateInOnChainSmtMtp[onChainLevels];
    signal input userStateInOnChainSmtMtpAuxHi;
    signal input userStateInOnChainSmtMtpAuxHv;
    signal input userStateInOnChainSmtMtpNoAux;

    /* id ownership check */
    component IdOwnership = VerifyAuthentication(IdOwnershipLevels);

    IdOwnership.userClaimsTreeRoot <== userClaimsTreeRoot;
    for (var i=0; i<IdOwnershipLevels; i++) {IdOwnership.userAuthClaimMtp[i] <== userAuthClaimMtp[i];}
    for (var i=0; i<8; i++) { IdOwnership.userAuthClaim[i] <== userAuthClaim[i]; }

    IdOwnership.userRevTreeRoot <== userRevTreeRoot;
    for (var i=0; i<IdOwnershipLevels; i++) { IdOwnership.userAuthClaimNonRevMtp[i] <== userAuthClaimNonRevMtp[i]; }
    IdOwnership.userAuthClaimNonRevMtpNoAux <== userAuthClaimNonRevMtpNoAux;
    IdOwnership.userAuthClaimNonRevMtpAuxHv <== userAuthClaimNonRevMtpAuxHv;
    IdOwnership.userAuthClaimNonRevMtpAuxHi <== userAuthClaimNonRevMtpAuxHi;

    IdOwnership.userRootsTreeRoot <== userRootsTreeRoot;

    IdOwnership.challenge <== challenge;
    IdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    IdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    IdOwnership.challengeSignatureS <== challengeSignatureS;

    IdOwnership.userState <== userState;
    IdOwnership.userID <== userID;

    /* Check on-chain SMT inclusion existence */
    component cutId = cutId();
    cutId.in <== userID;

    component cutState = cutState();
    cutState.in <== userState;

    component isCutIdEqualToCutState = IsEqual();
    isCutIdEqualToCutState.in[0] <== cutId.out;
    isCutIdEqualToCutState.in[1] <== cutState.out;

    component onChainSmtInclusion = SMTVerifier(onChainLevels);
    onChainSmtInclusion.enabled <== 1;
    onChainSmtInclusion.fnc <== isCutIdEqualToCutState.out; // non-inclusion in case if genesis state, otherwise inclusion
    onChainSmtInclusion.root <== userStateInOnChainSmtRoot;
    for (var i=0; i<onChainLevels; i++) { onChainSmtInclusion.siblings[i] <== userStateInOnChainSmtMtp[i]; }
    onChainSmtInclusion.oldKey <== userStateInOnChainSmtMtpAuxHi;
    onChainSmtInclusion.oldValue <== userStateInOnChainSmtMtpAuxHv;
    onChainSmtInclusion.isOld0 <== userStateInOnChainSmtMtpNoAux;
    onChainSmtInclusion.key <== userID;
    onChainSmtInclusion.value <== userState;

    /* Nullifier calculation */
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== userID;
    poseidon.inputs[1] <== userSalt;
    userNullifier <== poseidon.out;
}
