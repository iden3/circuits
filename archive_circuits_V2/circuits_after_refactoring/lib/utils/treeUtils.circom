pragma circom 2.1.1;

include "../../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../../node_modules/circomlib/circuits/mux1.circom";
include "claimUtils.circom";

// checkClaimExists verifies that claim is included into the claim tree root
template checkClaimExists(IssuerLevels) {
    signal input enabled;
	signal input claim[8];
	signal input claimMTP[IssuerLevels];
	signal input treeRoot;

	component claimHiHv = getClaimHiHv();
	claimHiHv.claim <== claim;

	SMTVerifier(IssuerLevels)(
	    enabled <== enabled,  // enabled
        root <== treeRoot, // root
        siblings <== claimMTP, // siblings
        oldKey <== 0, // oldKey
        oldValue <== 0, // oldValue
        isOld0 <== 0, // isOld0
        key <== claimHiHv.hi, // key
        value <== claimHiHv.hv, // value
        fnc <== 0 // fnc = inclusion
    );
}

template checkClaimNotRevoked(treeLevels) {
	signal input enabled;
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
    signal input enabled;
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

// verifyClaimIssuanceNonRev verifies that claim is issued by the issuer and not revoked
// TODO: review if we need both verifyClaimIssuanceNonRev and verifyClaimIssuance
template verifyClaimIssuanceNonRev(IssuerLevels) {
	signal input claim[8];
	signal input claimIssuanceMtp[IssuerLevels];
	signal input claimIssuanceClaimsTreeRoot;
	signal input claimIssuanceRevTreeRoot;
	signal input claimIssuanceRootsTreeRoot;
	signal input claimIssuanceIdenState;

	signal input enabledNonRevCheck;
	signal input claimNonRevMtp[IssuerLevels];
	signal input claimNonRevMtpNoAux;
	signal input claimNonRevMtpAuxHi;
	signal input claimNonRevMtpAuxHv;
	signal input claimNonRevIssuerClaimsTreeRoot;
	signal input claimNonRevIssuerRevTreeRoot;
	signal input claimNonRevIssuerRootsTreeRoot;
	signal input claimNonRevIssuerState;

    verifyClaimIssuance(IssuerLevels)(
        1,
        claim,
        claimIssuanceMtp,
        claimIssuanceClaimsTreeRoot,
        claimIssuanceRevTreeRoot,
        claimIssuanceRootsTreeRoot,
        claimIssuanceIdenState
    );

    // check non-revocation proof for claim
    checkClaimNotRevoked(IssuerLevels)(
        enabledNonRevCheck,
        claim,
        claimNonRevMtp,
        claimIssuanceRevTreeRoot,
        claimNonRevMtpNoAux,
        claimNonRevMtpAuxHi,
        claimNonRevMtpAuxHv
    );

    // check issuer state matches for non-revocation proof
    checkIdenStateMatchesRoots()(
        1,
        claimNonRevIssuerClaimsTreeRoot,
        claimNonRevIssuerRevTreeRoot,
        claimNonRevIssuerRootsTreeRoot,
        claimNonRevIssuerState
    );
}

// verifyClaimIssuance verifies that claim is issued by the issuer
template verifyClaimIssuance(IssuerLevels) {
    signal input enabled;
	signal input claim[8];
	signal input claimIssuanceMtp[IssuerLevels];
	signal input claimIssuanceClaimsTreeRoot;
	signal input claimIssuanceRevTreeRoot;
	signal input claimIssuanceRootsTreeRoot;
	signal input claimIssuanceIdenState;

    // verify country claim is included in claims tree root
    checkClaimExists(IssuerLevels)(
        enabled,
        claim,
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
    signal input enabled;

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

    // AuthHash cca3371a6cb1b715004407e325bd993c
    // BigInt: 80551937543569765027552589160822318028
    // https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential
    verifyCredentialSchema()(
        enabled,
        authClaim,
        80551937543569765027552589160822318028
    );

    checkClaimExists(nLevels)(
        1,
        authClaim,
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
        authClaim,
        challengeSignatureS,
        challengeSignatureR8x,
        challengeSignatureR8y,
        challenge
    );
}
