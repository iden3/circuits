
pragma circom 2.1.1;

include "../../node_modules/circomlib/circuits/babyjub.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "utils/safeOne.circom";
include "idOwnership.circom";

template StateTransition(IdOwnershipLevels) {
    signal input userID;
    signal input oldUserState;
    signal input newUserState;
    signal input isOldStateGenesis;

    signal input claimsTreeRoot;
    signal input authClaimMtp[IdOwnershipLevels];
    signal input authClaim[8];

    signal input revTreeRoot;
    signal input authClaimNonRevMtp[IdOwnershipLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHv;
    signal input authClaimNonRevMtpAuxHi;

    signal input rootsTreeRoot;

    signal input signatureR8x;
    signal input signatureR8y;
    signal input signatureS;

    signal input newClaimsTreeRoot;
    signal input newAuthClaimMtp[IdOwnershipLevels];
    signal input newRevTreeRoot;
    signal input newRootsTreeRoot;

    // get safe one values to be used in ForceEqualIfEnabled
    signal one <== SafeOne()(userID);

    signal cutId <== cutId()(userID);

    signal cutState <== cutState()(oldUserState);

    signal isCutIdEqualToCutState <== IsEqual()([cutId, cutState]);

    // if isOldStateGenesis != 0 then old state is genesis
    // and we must check that userID was derived from that state
    (1 - isCutIdEqualToCutState) * isOldStateGenesis === 0;

    // check newUserState is not zero
    signal stateIsNotZero <== IsZero()(newUserState);
    ForceEqualIfEnabled()(one, [stateIsNotZero, 0]);

    // old & new state checks
    signal oldNewNotEqual <== IsEqual()([oldUserState, newUserState]);
    ForceEqualIfEnabled()(one, [oldNewNotEqual, 0]);

    // check userID ownership by correct signature of a hash of old state and new state
    signal challenge <== Poseidon(2)([oldUserState, newUserState]);

    IdOwnership(IdOwnershipLevels)(
        one,
        oldUserState,
        claimsTreeRoot,
        authClaimMtp,
        authClaim,
        revTreeRoot,
        authClaimNonRevMtp,
        authClaimNonRevMtpNoAux,
        authClaimNonRevMtpAuxHi,
        authClaimNonRevMtpAuxHv,
        rootsTreeRoot,
        challenge,
        signatureR8x,
        signatureR8y,
        signatureS
    );

    signal authClaimHi, authClaimHv;
	(authClaimHi, authClaimHv) <== getClaimHiHv()(authClaim);

    // check auth claim exists in newClaimsTreeRoot and newUserState
    checkClaimExists(IdOwnershipLevels)(one, authClaimHi, authClaimHv, newAuthClaimMtp, newClaimsTreeRoot);

    checkIdenStateMatchesRoots()(one, newClaimsTreeRoot, newRevTreeRoot, newRootsTreeRoot, newUserState);
}
