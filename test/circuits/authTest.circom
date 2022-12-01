pragma circom 2.0.0;

include "../../circuits/lib/auth.circom";

component main {public [userID,challenge,userState]} = Auth(32);
