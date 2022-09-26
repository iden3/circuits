pragma circom 2.0.0;

include "auth.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template AuthV2(IdOwnershipLevels, onChainLevels) {

    signal input userClearTextID;
    signal input userState;
    signal input userSalt;
    // userID output signal will be assigned with nullifier hash(UserID, userSalt),
    // unless userSalt == 0, in which case userID will be assigned with userClearTextID
    signal output userID;

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
    component IdOwnership = Auth(IdOwnershipLevels);

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
    IdOwnership.userID <== userClearTextID;

    /* Check on-chain SMT inclusion existence */
    component cutId = cutId();
    cutId.in <== userClearTextID;

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
    onChainSmtCheck.key <== userClearTextID;
    onChainSmtCheck.value <== userState;

    /* Nullifier calculation */
    component calcNullifier = Poseidon(2);
    calcNullifier.inputs[0] <== userClearTextID;
    calcNullifier.inputs[1] <== userSalt;

    component isSaltZero = IsZero();
    isSaltZero.in <== userSalt;

    component selectNul = Mux1();
    selectNul.s <== isSaltZero.out;
    selectNul.c[0] <== calcNullifier.out;
    selectNul.c[1] <== userClearTextID;
    userID <== selectNul.out;
}
