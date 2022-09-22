pragma circom 2.0.0;

include "../../circuits/lib/authentication.circom";

component main {public [userID,challenge,userState]} = VerifyAuthentication(32);
