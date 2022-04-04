pragma circom 2.0.0;

include "../../circuits/lib/authenticationWithRelay.circom";

component main {public [challenge,state]} = VerifyAuthenticationWithRelay(40, 4);
