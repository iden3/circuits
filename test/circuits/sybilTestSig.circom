pragma circom 2.0.0;

include "../../circuits/sybil/sybilResCredentialAtomicQuerySigOffChain.circom";

component main{public [
                        // uniqueness claim
                        issuerClaimNonRevState,

                        // state secret claim
                        crs,
                        gistRoot
]} = SybilResCredentialAtomicQuerySigOffChain(32, 32, 32);