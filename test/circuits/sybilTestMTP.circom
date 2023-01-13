pragma circom 2.0.0;

include "../../circuits/sybil/sybilCredentialAtomicMTPOffChain.circom";

component main{public [
                        requestID,
                        issuerID,
                        timestamp,
                        claimSchema,
                        issuerClaimIdenState,
                        issuerClaimNonRevState,
                        crs,
                        gistRoot]} = SybilCredentialAtomicMTP(32, 32, 32);