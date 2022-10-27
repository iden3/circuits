pragma circom 2.0.0;

include "credentialAtomicQuerySigOffChain.circom";

/*

*/
component main{public [issuerID,
                       issuerClaimNonRevState,
                       claimSchema,
                       slotIndex,
                       operator,
                       value,
                       timestamp]} = credentialAtomicQuerySigV2(32, 32, 64);
