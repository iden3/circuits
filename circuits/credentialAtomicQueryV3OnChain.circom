pragma circom 2.1.1;

include "./onchain/credentialAtomicQueryV3OnChain.circom";

/*
 public output signals:
 userID - user profile id
 merklized - `1` if claim is merklized
 issuerState - equals to issuerAuthState for sig, and to issuerClaimIdenState for mtp
*/
component main{public [requestID,
                       issuerID,
                       issuerClaimNonRevState,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot,
                       proofType,
                       verifierID
                       ]} = credentialAtomicQueryV3OnChain(40, 32, 64, 40, 64);
