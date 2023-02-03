pragma circom 2.0.0;

include "credentialAtomicQuerySigOffChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
 issuerAuthState
*/
component main{public [requestID,
                       issuerID,
                       issuerClaimNonRevState,
                       claimSchema,
                       slotIndex,
                       claimPathKey,
                       claimPathNotExists,
                       operator,
                       value,
                       timestamp, isRevocationChecked]} = credentialAtomicQuerySigOffChain(40, 32, 64);
