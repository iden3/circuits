pragma circom 2.1.1;

include "offchain/credentialAtomicQuerySigOffChain.circom";

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
