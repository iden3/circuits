pragma circom 2.0.0;

include "lib/authenticationOnChainSmt.circom";

component main {public [userID,challenge,userState]} = VerifyAuthenticationOnChainSmt(32,32);
