pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";

// Circuit for calculating the v0 part of the claim value:
// https://docs.iden3.io/protocol/claims-structure/
template V0Calculator() {
    signal input revocation;
    signal input expiration;
    signal output out;

    component revocationBytes = Num2Bits(64);
    revocationBytes.in <== revocation;

    component expirationBytes = Num2Bits(64);
    expirationBytes.in <== expiration;

    component v0 = Bits2Num(128);
    for (var i=0; i<64; i++) {
        v0.in[i] <== revocationBytes.out[i];
        v0.in[i+64] <== expirationBytes.out[i];
    }

    out <== v0.out;
}