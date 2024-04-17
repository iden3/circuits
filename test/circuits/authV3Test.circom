pragma circom 2.1.1;

include "../../circuits/auth/authV3.circom";

component main {public [challenge, gistRoot]} = AuthV3(32,32);
