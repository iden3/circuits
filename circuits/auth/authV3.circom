pragma circom 2.1.1;

include "../../node_modules/circomlib/circuits/mux1.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../lib/idOwnership.circom";
include "../lib/utils/idUtils.circom";
include "../lib/utils/safeOne.circom";

template AuthV3(IdOwnershipLevels, onChainLevels) {
    signal input genesisID;
    // random number, which should be stored by user if there is a need to
    // generate the same userID (ProfileID) output for different proofs
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

    // challenge and it's signature
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

    // get safe zero and one values to be used in ForceEqualIfEnabled
    signal {binary} one <== SafeOne()(genesisID);

    checkAuthV3(IdOwnershipLevels, onChainLevels)(
        one,
        genesisID,
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

template checkAuthV3(IdOwnershipLevels, onChainLevels) {
    signal input {binary} enabled;

    signal input genesisID;

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

    /* Check if state is genesis and if genesisId is valid */

    signal cutState <== cutState()(state);

    component genesisIdParts = SplitID();
    genesisIdParts.id <== genesisID;

    signal calculatedChecksum <== CalculateIdChecksum()(genesisIdParts.typ, genesisIdParts.genesis);
    ForceEqualIfEnabled()(
        enabled,
        [genesisIdParts.checksum, calculatedChecksum]
    );

    signal isStateGenesis <== IsEqual()([genesisIdParts.genesis, cutState]);

    /* Check on-chain SMT inclusion existence */

    signal genesisIDHash <== Poseidon(1)([genesisID]);

    SMTVerifier(onChainLevels)(
        enabled <== enabled,
        fnc <== isStateGenesis, // non-inclusion in case of genesis state, otherwise inclusion
        root <== gistRoot,
        siblings <== gistMtp,
        oldKey <== gistMtpAuxHi,
        oldValue <== gistMtpAuxHv,
        isOld0 <== gistMtpNoAux,
        key <== genesisIDHash,
        value <== state
    );
}
