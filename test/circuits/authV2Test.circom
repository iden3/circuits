pragma circom 2.0.0;

include "../../circuits/lib/authV2.circom";

component main {public [challenge, globalSmtRoot]} = AuthV2(32,32);
