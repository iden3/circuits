pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "claimUtils.circom";

// getIdenState caclulates the Identity state out of the claims tree root,
// revocations tree root and roots tree root.
template getIdenState() {
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;

	signal output idenState <== Poseidon(3)([
	    claimsTreeRoot,
	    revTreeRoot,
	    rootsTreeRoot
	]);
}

// checkClaimExists verifies that claim is included into the claim tree root
template checkClaimExists(IssuerLevels) {
	signal input claim[8];
	signal input claimMTP[IssuerLevels];
	signal input treeRoot;

	component claimHiHv = getClaimHiHv();
	claimHiHv.claim <== claim;

	SMTVerifier(IssuerLevels)(
	    enabled <== 1,  // enabled
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
	signal input claimsTreeRoot;
	signal input revTreeRoot;
	signal input rootsTreeRoot;
	signal input expectedState;

    signal idenState <== getIdenState()(
        claimsTreeRoot,
        revTreeRoot,
        rootsTreeRoot
    );

    // TODO: use IsEqual component
	idenState === expectedState;
}

// verifyClaimIssuance verifies that claim is issued by the issuer and not revoked
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

    // verify country claim is included in claims tree root
    checkClaimExists(IssuerLevels)(
        claim,
        claimIssuanceMtp,
        claimIssuanceClaimsTreeRoot
    );

    // verify issuer state includes country claim
    checkIdenStateMatchesRoots()(
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
        claimNonRevIssuerClaimsTreeRoot,
        claimNonRevIssuerRevTreeRoot,
        claimNonRevIssuerRootsTreeRoot,
        claimNonRevIssuerState
    );
}

template VerifyAuthClaimAndSignature(nLevels) {
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
        authClaim,
        80551937543569765027552589160822318028
    );

    checkClaimExists(nLevels)(
        authClaim,
        authClaimMtp,
        claimsTreeRoot
    );

    checkClaimNotRevoked(nLevels)(
        1,
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

template cutId() {
	signal input in;
	signal output out;

	signal idBits[256] <== Num2Bits(256)(in);

	component cutted = Bits2Num(256-16-16-8);
	for (var i=16; i<256-16-8; i++) {
		cutted.in[i-16] <== idBits[i];
	}
	out <== cutted.out;
}

template cutState() {
	signal input in;
	signal output out;

	signal stateBits[256] <== Num2Bits(256)(in);

	component cutted = Bits2Num(256-16-16-8);
	for (var i=0; i<256-16-16-8; i++) {
		cutted.in[i] <== stateBits[i+16+16+8];
	}
	out <== cutted.out;
}
