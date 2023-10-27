pragma circom 2.1.1;

include "../lib/idOwnership.circom";
include "../lib/utils/idUtils.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";

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

    checkAuthV2(IdOwnershipLevels, onChainLevels)(
        1,
        genesisID,
        profileNonce,
        state,
        claimsTreeRoot,
        revTreeRoot,
        rootsTreeRoot,
        authClaim,
        authClaimIncMtp,
        authClaimNonRevMtp,
        authClaimNonRevMtpNoAux,
        authClaimNonRevMtpAuxHi,
        authClaimNonRevMtpAuxHv,
        challenge,
        challengeSignatureR8x,
        challengeSignatureR8y,
        challengeSignatureS,
        gistRoot,
        gistMtp,
        gistMtpAuxHi,
        gistMtpAuxHv,
        gistMtpNoAux
    );

    /* ProfileID calculation */
    userID <== SelectProfile()(genesisID, profileNonce);
}

template checkAuthV2(IdOwnershipLevels, onChainLevels) {
    signal input enabled;

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

    /* id ownership check */
    IdOwnership(IdOwnershipLevels)(
        enabled,
        state,
        claimsTreeRoot,
        authClaimIncMtp,
        authClaim,
        revTreeRoot,
        authClaimNonRevMtp,
        authClaimNonRevMtpNoAux,
        authClaimNonRevMtpAuxHi,
        authClaimNonRevMtpAuxHv,
        rootsTreeRoot,
        challenge,
        challengeSignatureR8x,
        challengeSignatureR8y,
        challengeSignatureS
    );

    /* Check on-chain SMT inclusion existence */
    signal cutId <== cutId()(genesisID);

    signal cutState <== cutState()(state);

    signal isStateGenesis <== IsEqual()([cutId, cutState]);

    signal genesisIDhash <== Poseidon(1)([genesisID]);

    SMTVerifier(onChainLevels)(
        enabled <== enabled,
        fnc <== isStateGenesis, // non-inclusion in case if genesis state, otherwise inclusion
        root <== gistRoot,
        siblings <== gistMtp,
        oldKey <== gistMtpAuxHi,
        oldValue <== gistMtpAuxHv,
        isOld0 <== gistMtpNoAux,
        key <== genesisIDhash,
        value <== state
    );
}
