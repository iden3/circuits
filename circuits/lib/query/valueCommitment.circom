pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

/**
Value commitment circuit allows to commit to a specific value and then
reveal it later or use such a commitment in another circuits to prove that
multiple circuits work with the same value without revealing it.
*/

template ValueCommitment() {
    signal input value;
    signal input commitNonce; // private random nonce to make the commitment unique and secure

    signal output out;

    signal isNonceZero <== IsZero()(commitNonce);

    signal commit <== Poseidon(2)([value, commitNonce]);

    out <== Mux1()(
        [commit, 0],
        isNonceZero
    );
}
