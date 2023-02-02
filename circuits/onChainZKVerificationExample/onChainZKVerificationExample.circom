pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template OnChainZKVerificationExample() {
    signal input issuerPubKeyAx;
    signal input issuerPubKeyAy;
    signal input issuerClaimSignatureR8x;
    signal input issuerClaimSignatureR8y;
    signal input issuerClaimSignatureS;
    signal input userEthereumAddressInClaim;
    signal input userAgeInClaim;
    signal input userMinAge;

    // Hash claim
    component hashClaim = Poseidon(2);
    hashClaim.inputs[0] <== userEthereumAddressInClaim;
    hashClaim.inputs[1] <== userAgeInClaim;

    // Check claim signature
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;

    sigVerifier.Ax <== issuerPubKeyAx;
    sigVerifier.Ay <== issuerPubKeyAy;

    sigVerifier.S <== issuerClaimSignatureS;
    sigVerifier.R8x <== issuerClaimSignatureR8x;
    sigVerifier.R8y <== issuerClaimSignatureR8y;

    sigVerifier.M <== hashClaim.out;

    // Check age in the claim
    component ageVerifier = LessEqThan(252);
    ageVerifier.in[0] <== userMinAge;
    ageVerifier.in[1] <== userAgeInClaim;
    ageVerifier.out === 1;
}
