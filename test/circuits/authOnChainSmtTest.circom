pragma circom 2.0.0;

include "../../circuits/lib/authenticationOnChainSmt.circom";

component main {public [challenge,userState]} = VerifyAuthenticationOnChainSmt(32,32);
