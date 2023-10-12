pragma circom 2.1.1;

include "../../../node_modules/circomlib/circuits/mux3.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/mux2.circom";
include "./claimUtils.circom";

template getClaimSubjectOtherIdenWrapper() {
    signal input claim[8];
    signal output id;

    // get header flags from claim.
    component header = getClaimHeader();
    header.claim <== claim;

    id <== getClaimSubjectOtherIden()(claim, header.claimFlags);
}
