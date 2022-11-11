pragma circom 2.0.0;

include "credentialAtomicQuerySigOffChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
*/
component main{public [issuerID,
                       issuerClaimNonRevState,
                       claimSchema,
                       slotIndex,
                       claimPathKey,
                       claimPathNotExists,
                       operator,
                       value,
                       timestamp]} = credentialAtomicQuerySigOffChain(32, 32, 64);
