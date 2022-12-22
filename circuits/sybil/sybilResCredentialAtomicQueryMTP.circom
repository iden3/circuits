pragma circom 2.0.0;

include "sybilResCredentialAtomicQueryMTPOffChain.circom";

component main{public [
                        // uniqueness claim
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        issuerClaimSchema,
                        
                        // state secret claim
                        holderClaimSchema,  // <--- should be hard coded 
                        crs,
                        gistRoot
                    ]} = SybilResCredentialAtomicQueryMTPOffChain(32, 32, 32);
