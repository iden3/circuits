pragma circom 2.0.0;

include "idOwnership.circom";
include "./utils/idUtils.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template AuthV2(IdOwnershipLevels, onChainLevels) {

    signal input userGenesisID;
    signal input userState;
    signal input nonce; // random number

    // user state
    signal input userClaimsTreeRoot;
    signal input userRevTreeRoot;
    signal input userRootsTreeRoot;

    // Auth claim
    signal input userAuthClaim[8];

    // auth claim. merkle tree proof of inclusion to claim tree
    signal input userAuthClaimMtp[IdOwnershipLevels];

    // auth claim - rev nonce. merkle tree proof of non-inclusion to rev tree
    signal input userAuthClaimNonRevMtp[IdOwnershipLevels];
    signal input userAuthClaimNonRevMtpNoAux;
    signal input userAuthClaimNonRevMtpAuxHi;
    signal input userAuthClaimNonRevMtpAuxHv;

    // challenge signature
    signal input challenge;
    signal input challengeSignatureR8x;
    signal input challengeSignatureR8y;
    signal input challengeSignatureS;

    // global on chain state
    signal input globalSmtRoot;
    // proof of inclusion or exclusion of the user in the global state
    signal input globalSmtMtp[onChainLevels];
    signal input globalSmtMtpAuxHi;
    signal input globalSmtMtpAuxHv;
    signal input globalSmtMtpNoAux;

    // userID output signal will be assigned with user profile hash(UserID, nonce),
    // unless nonce == 0, in which case userID will be assigned with userGenesisID
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

    component userGenesisIDhash = Poseidon(1);
    userGenesisIDhash.inputs[0] <== userGenesisID;

    component onChainSmtCheck = SMTVerifier(onChainLevels);
    onChainSmtCheck.enabled <== 1;
    onChainSmtCheck.fnc <== isStateGenesis.out; // non-inclusion in case if genesis state, otherwise inclusion
    onChainSmtCheck.root <== globalSmtRoot;
    for (var i=0; i<onChainLevels; i++) { onChainSmtCheck.siblings[i] <== globalSmtMtp[i]; }
    onChainSmtCheck.oldKey <== globalSmtMtpAuxHi;
    onChainSmtCheck.oldValue <== globalSmtMtpAuxHv;
    onChainSmtCheck.isOld0 <== globalSmtMtpNoAux;
    onChainSmtCheck.key <== userGenesisIDhash.out;
    onChainSmtCheck.value <== userState;

    /* ProfileID calculation */
    component calcProfile = ProfileID();
    calcProfile.in <== userGenesisID;
    calcProfile.nonce <== nonce;

    component isSaltZero = IsZero();
    isSaltZero.in <== nonce;

    component selectProfile = Mux1();
    selectProfile.s <== isSaltZero.out;
    selectProfile.c[0] <== calcProfile.out;
    selectProfile.c[1] <== userGenesisID;

    userID <== selectProfile.out;
}
