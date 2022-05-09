pragma circom 2.0.0;

include "../../circuits/lib/authenticationWithRelay.circom";

component main {public [challenge,userState]} = VerifyAuthenticationWithRelay(32, 4);
