pragma circom 2.1.1;

include "universal/credentialAtomicQueryV3Universal.circom";

/*
public outputsignal s:
userID - user profile id
merklized - `1` if claim is merklized
issuerState - equals to issuerAuthState for sig, and to issuerClaimIdenState for mtp
nullifier - sybil resistant user identifier for session id
linkID - linked proof identifier
circuitQueryHash - hash of the query
*/
component main{public [requestID,
    issuerID,
    issuerClaimNonRevState,
    claimSchema,
    slotIndex,
    claimPathKey,
    operator,
    value,
    valueArraySize,
    timestamp,
    isRevocationChecked,
    proofType,
    verifierID,
    nullifierSessionID
]} = credentialAtomicQueryV3Universal(16, 16, 64); // issuerLevels, claimLevels, maxValueArraySize
