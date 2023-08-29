pragma circom 2.1.1;

include "../../circuits/auth/authV2.circom";

component main {public [challenge, gistRoot]} = AuthV2(32,32);
