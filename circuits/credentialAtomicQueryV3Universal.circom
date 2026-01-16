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
    timestamp,
    proofType
]} = credentialAtomicQueryV3Universal(40, 32, 64); // issuerLevels, claimLevels, maxValueArraySize
