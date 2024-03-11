pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "claimUtils.circom";

// checkClaimExists verifies that claim is included into the claim tree root
template checkClaimExists(IssuerLevels) {
    signal input {binary} enabled;
	signal input claimHi;
	signal input claimHv;
	signal input claimMTP[IssuerLevels];
	signal input treeRoot;

	SMTVerifier(IssuerLevels)(
	    enabled <== enabled,  // enabled
        root <== treeRoot, // root
        siblings <== claimMTP, // siblings
        oldKey <== 0, // oldKey
        oldValue <== 0, // oldValue
        isOld0 <== 0, // isOld0
        key <== claimHi, // key
        value <== claimHv, // value
        fnc <== 0 // fnc = inclusion
    );
}

template checkClaimNotRevoked(treeLevels) {
	signal input {binary} enabled;
    signal input claim[8];
    signal input claimNonRevMTP[treeLevels];
    signal input treeRoot;
    signal input noAux;
    signal input auxHi;
    signal input auxHv;

	signal claimRevNonce <== getClaimRevNonce()(claim);

    SMTVerifier(treeLevels)(
        enabled <== enabled,
        root <== treeRoot,
        siblings <== claimNonRevMTP,
        oldKey <== auxHi,
        oldValue <== auxHv,
        isOld0 <== noAux,
        key <== claimRevNonce,
        value <== 0,
        fnc <== 1 // Non-inclusion
    );
}

// checkIdenStateMatchesRoots checks that a hash of 3 tree
// roots is equal to expected identity state
template checkIdenStateMatchesRoots() {
    signal input {binary} enabled;
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;
	signal input expectedState;

    signal idenState <== getIdenState()(
        claimsTreeRoot,
        revTreeRoot,
        rootsTreeRoot
    );

    ForceEqualIfEnabled()(
        enabled,
        [idenState, expectedState]
    );
}

// verifyClaimIssuance verifies that claim is issued by the issuer
template verifyClaimIssuance(IssuerLevels) {
    signal input {binary} enabled;
	signal input claimHi;
	signal input claimHv;
	signal input claimIssuanceMtp[IssuerLevels];
	signal input claimIssuanceClaimsTreeRoot;
	signal input claimIssuanceRevTreeRoot;
	signal input claimIssuanceRootsTreeRoot;
	signal input claimIssuanceIdenState;

    // verify country claim is included in claims tree root
    checkClaimExists(IssuerLevels)(
        enabled,
        claimHi,
        claimHv,
        claimIssuanceMtp,
        claimIssuanceClaimsTreeRoot
    );

    // verify issuer state includes country claim
    checkIdenStateMatchesRoots()(
        enabled,
        claimIssuanceClaimsTreeRoot,
        claimIssuanceRevTreeRoot,
        claimIssuanceRootsTreeRoot,
        claimIssuanceIdenState
    );
}

template VerifyAuthClaimAndSignature(nLevels) {
    signal input {binary} enabled;

	signal input claimsTreeRoot;
	signal input authClaimMtp[nLevels];
	signal input authClaim[8];

	signal input revTreeRoot;
    signal input authClaimNonRevMtp[nLevels];
    signal input authClaimNonRevMtpNoAux;
    signal input authClaimNonRevMtpAuxHi;
    signal input authClaimNonRevMtpAuxHv;

	signal input challenge;
	signal input challengeSignatureR8x;
	signal input challengeSignatureR8y;
	signal input challengeSignatureS;

    component authClaimHeader = getClaimHeader();
    authClaimHeader.claim <== authClaim;

    // AuthHash cca3371a6cb1b715004407e325bd993c
    // BigInt: 80551937543569765027552589160822318028
    // https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential
    verifyCredentialSchema()(
        enabled,
        authClaimHeader.schema,
        80551937543569765027552589160822318028
    );

    signal authClaimHi, authClaimHv;
	(authClaimHi, authClaimHv) <== getClaimHiHv()(authClaim);

    checkClaimExists(nLevels)(
        enabled,
        authClaimHi,
        authClaimHv,
        authClaimMtp,
        claimsTreeRoot
    );

    checkClaimNotRevoked(nLevels)(
        enabled,
        authClaim,
        authClaimNonRevMtp,
        revTreeRoot,
        authClaimNonRevMtpNoAux,
        authClaimNonRevMtpAuxHi,
        authClaimNonRevMtpAuxHv
    );

    checkDataSignatureWithPubKeyInClaim()(
        enabled,
        authClaim,
        challengeSignatureS,
        challengeSignatureR8x,
        challengeSignatureR8y,
        challenge
    );

    // explicitly state that some of these signals are not used and it's ok
    for (var i=0; i<32; i++) {
        _ <== authClaimHeader.claimFlags[i];
    }
}
