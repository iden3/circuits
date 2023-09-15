pragma circom 2.1.5;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../utils/claimUtils.circom";

template LinkID() {
    signal input claim[8];
    signal input linkNonce;

    signal output out;

    signal isNonceZero <== IsZero()(linkNonce);

    component claimHash = getClaimHash();
    claimHash.claim <== claim;

    signal linkID <== Poseidon(2)([claimHash.hash, linkNonce]);

    out <== Mux1()(
        [linkID, 0],
        isNonceZero
    );
}
