pragma circom 2.0.0;

include "../../circuits/authenticationWithRelay.circom";

component main {public [challenge,state]} = VerifyAuthenticationInformationWithRelay(40, 4);
