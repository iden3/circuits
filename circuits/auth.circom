pragma circom 2.0.0;

include "auth/auth.circom";

component main {public [userID,challenge,userState]} = Auth(32);
