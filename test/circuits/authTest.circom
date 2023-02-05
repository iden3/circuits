pragma circom 2.0.0;

include "../../circuits/auth/auth.circom";

component main {public [userID,challenge,userState]} = Auth(32);
