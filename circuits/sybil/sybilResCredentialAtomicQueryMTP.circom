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


// Public
// ---------
// IssuerState (states, 1-state: for the issuance of the kyc-claim, 2-state: latest state of the issuer)
// kycClaimSchemaID (~claim_of_uniqueness)
// stateCommitmentSchemaID - need to be defined
// Reference GIST 
// CRS
//

component main{public [
                        // uniqueness claim
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        issuerClaimSchema,
                        
                        // state secret claim
                        holderClaimSchema,  // <--- should be hard coded 
                        crs,
                        gistRoot
                    ]} = SybilResCredentialAtomicQueryMTPOffChain(32, 32);
