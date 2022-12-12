pragma circom 2.0.0;

include "sybilResCredentialAtomicQueryMTPOffChain.circom";

/*
 public signals:
 userID - user profile id
 merklized - `1` if claim is merklized
*/
// component main{public [requestID,
//                        issuerID,
//                        issuerClaimIdenState,
//                        issuerClaimNonRevState,
//                        claimSchema,
//                        slotIndex,
//                        claimPathKey,
//                        claimPathNotExists,
//                        operator,
//                        value,
//                        timestamp]} = SybilResCredentialAtomicQueryMTPOffChain(32, 32, 64);

component main{public []} = SybilResCredentialAtomicQueryMTPOffChain(32, 32, 64);
