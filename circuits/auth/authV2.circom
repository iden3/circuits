pragma circom 2.0.0;

include "../lib/idOwnership.circom";
include "../lib/utils/idUtils.circom";
include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template AuthV2(IdOwnershipLevels, onChainLevels) {

    signal input genesisID;
    // random number, which should be stored by user
    // if there is a need to generate the same userID (ProfileID) output for different proofs
    signal input profileNonce;

    // user state
    signal input state;
    signal input claimsTreeRoot;
    signal input revTreeRoot;
    signal input rootsTreeRoot;

    // Auth claim
    signal input authClaim[8];

    // auth claim. merkle tree proof of inclusion to claim tree
    signal input authClaimIncMtp[IdOwnershipLevels];

    // auth claim - rev nonce. merkle tree proof of non-inclusion to rev tree
    signal input authClaimNonRevMtp[IdOwnershipLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

    // challenge signature
    signal input challenge;
    signal input challengeSignatureR8x;
    signal input challengeSignatureR8y;
    signal input challengeSignatureS;

    // global identity state tree on chain
    signal input gistRoot;
    // proof of inclusion or exclusion of the user in the global state
    signal input gistMtp[onChainLevels];
    signal input gistMtpAuxHi;
    signal input gistMtpAuxHv;
    signal input gistMtpNoAux;

    // userID output signal will be assigned with user profile hash(UserID, nonce),
    // unless nonce == 0, in which case userID will be assigned with userGenesisID
    signal output userID;



    /* id ownership check */
    component checkIdOwnership = IdOwnership(IdOwnershipLevels);

    checkIdOwnership.userClaimsTreeRoot <== claimsTreeRoot;
    for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimMtp[i] <== authClaimIncMtp[i]; }
    for (var i=0; i<8; i++) { checkIdOwnership.userAuthClaim[i] <== authClaim[i]; }

    checkIdOwnership.userRevTreeRoot <== revTreeRoot;
    for (var i=0; i<IdOwnershipLevels; i++) { checkIdOwnership.userAuthClaimNonRevMtp[i] <== authClaimNonRevMtp[i]; }
    checkIdOwnership.userAuthClaimNonRevMtpNoAux <== authClaimNonRevMtpNoAux;
    checkIdOwnership.userAuthClaimNonRevMtpAuxHv <== authClaimNonRevMtpAuxHv;
    checkIdOwnership.userAuthClaimNonRevMtpAuxHi <== authClaimNonRevMtpAuxHi;

    checkIdOwnership.userRootsTreeRoot <== rootsTreeRoot;

    checkIdOwnership.challenge <== challenge;
    checkIdOwnership.challengeSignatureR8x <== challengeSignatureR8x;
    checkIdOwnership.challengeSignatureR8y <== challengeSignatureR8y;
    checkIdOwnership.challengeSignatureS <== challengeSignatureS;

    checkIdOwnership.userState <== state;

    /* Check on-chain SMT inclusion existence */
    component cutId = cutId();
    cutId.in <== genesisID;

    component cutState = cutState();
    cutState.in <== state;

    component isStateGenesis = IsEqual();
    isStateGenesis.in[0] <== cutId.out;
    isStateGenesis.in[1] <== cutState.out;

    component genesisIDhash = Poseidon(1);
    genesisIDhash.inputs[0] <== genesisID;

    component gistCheck = SMTVerifier(onChainLevels);
    gistCheck.enabled <== 1;
    gistCheck.fnc <== isStateGenesis.out; // non-inclusion in case if genesis state, otherwise inclusion
    gistCheck.root <== gistRoot;
    for (var i=0; i<onChainLevels; i++) { gistCheck.siblings[i] <== gistMtp[i]; }
    gistCheck.oldKey <== gistMtpAuxHi;
    gistCheck.oldValue <== gistMtpAuxHv;
    gistCheck.isOld0 <== gistMtpNoAux;
    gistCheck.key <== genesisIDhash.out;
    gistCheck.value <== state;

    /* ProfileID calculation */
    component calcProfile = SelectProfile();
    calcProfile.in <== genesisID;
    calcProfile.nonce <== profileNonce;

    userID <== calcProfile.out;
}
