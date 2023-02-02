pragma circom 2.0.0;

include "../../circuits/onChainZKVerificationExample/onChainZKVerificationExample.circom";

component main {public [issuerPubKeyAx, issuerPubKeyAy, userEthereumAddressInClaim, userMinAge]} = OnChainZKVerificationExample();
