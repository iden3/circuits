pragma circom 2.1.5;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

template LinkID() {
    signal input claimHash;
    signal input linkNonce;

    signal output out;

    signal isNonceZero <== IsZero()(linkNonce);

    signal linkID <== Poseidon(2)([claimHash, linkNonce]);

    out <== Mux1()(
        [linkID, 0],
        isNonceZero
    );
}
