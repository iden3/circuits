pragma circom 2.0.0;

include "lib/authV2.circom";

component main {public [challenge, userStateInOnChainSmtRoot]} = AuthV2(32,32);
