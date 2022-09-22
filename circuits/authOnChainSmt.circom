pragma circom 2.0.0;

include "lib/authenticationOnChainSmt.circom";

component main {public [challenge, userStateInOnChainSmtRoot]} = VerifyAuthenticationOnChainSmt(32,32);
