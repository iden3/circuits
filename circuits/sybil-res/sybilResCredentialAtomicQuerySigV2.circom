pragma circom 2.0.0;

include "sybilResCredentialAtomicQuerySigOffChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
 issuerAuthState
*/
// component main{public [requestID,
//                        issuerID,
//                        issuerClaimNonRevState,
//                        claimSchema,
//                        slotIndex,
//                        claimPathKey,
//                        claimPathNotExists,
//                        operator,
//                        value,
//                        timestamp]} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 64);

component main{public []} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 64);