pragma circom 2.1.1;

include "linked/nullifier.circom";

component main {public [verifierID, nullifierSessionID]} = LinkedNullifier();
