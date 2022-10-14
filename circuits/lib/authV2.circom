pragma circom 2.0.0;

include "idOwnership.circom";
include "./utils/idUtils.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template AuthV2(IdOwnershipLevels, onChainLevels) {

    signal input userGenesisID;
    signal input userState;
    signal input userSalt;

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

    // userID output signal will be assigned with nullifier hash(UserID, userSalt),
    // unless userSalt == 0, in which case userID will be assigned with userGenesisID
    signal output userID;

    /* id ownership check */
    component checkIdOwnership = IdOwnership(IdOwnershipLevels);

    checkIdOwnership.userClaimsTreeRoot <== userClaimsTreeRoot;
    for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimMtp[i] <== userAuthClaimMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.userAuthClaim[i] <== userAuthClaim[i]; }

    checkIdOwnership.userRevTreeRoot <== userRevTreeRoot;
    for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimNonRevMtp[i] <== userAuthClaimNonRevMtp[i]; }
    checkIdOwnership.userAuthClaimNonRevMtpNoAux <== userAuthClaimNonRevMtpNoAux;
    checkIdOwnership.userAuthClaimNonRevMtpAuxHv <== userAuthClaimNonRevMtpAuxHv;
    checkIdOwnership.userAuthClaimNonRevMtpAuxHi <== userAuthClaimNonRevMtpAuxHi;

    checkIdOwnership.userRootsTreeRoot <== userRootsTreeRoot;

    checkIdOwnership.challenge <== challenge;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;

    checkIdOwnership.userState <== userState;

    /* Check on-chain SMT inclusion existence */
    component cutId = cutId();
    cutId.in <== userGenesisID;

    component cutState = cutState();
    cutState.in <== userState;

    component isStateGenesis = IsEqual();
    isStateGenesis.in[0] <== cutId.out;
    isStateGenesis.in[1] <== cutState.out;

    component onChainSmtCheck = SMTVerifier(onChainLevels);
    onChainSmtCheck.enabled <== 1;
    onChainSmtCheck.fnc <== isStateGenesis.out; // non-inclusion in case if genesis state, otherwise inclusion
    onChainSmtCheck.root <== userStateInOnChainSmtRoot;
    for (var i=0; i<onChainLevels; i++) { onChainSmtCheck.siblings[i] <== userStateInOnChainSmtMtp[i]; }
    onChainSmtCheck.oldKey <== userStateInOnChainSmtMtpAuxHi;
    onChainSmtCheck.oldValue <== userStateInOnChainSmtMtpAuxHv;
    onChainSmtCheck.isOld0 <== userStateInOnChainSmtMtpNoAux;
    onChainSmtCheck.key <== userGenesisID;
    onChainSmtCheck.value <== userState;

    /* ProfileID calculation */
    component calcProfile = ProfileID();
    calcProfile.in <== userGenesisID;
    calcProfile.salt <== userSalt;

    component isSaltZero = IsZero();
    isSaltZero.in <== userSalt;

    component selectProfile = Mux1();
    selectProfile.s <== isSaltZero.out;
    selectProfile.c[0] <== calcProfile.out;
    selectProfile.c[1] <== userGenesisID;

    userID <== selectProfile.out;
}
