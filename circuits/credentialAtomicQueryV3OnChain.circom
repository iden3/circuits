pragma circom 2.1.1;

include "./onchain/credentialAtomicQueryV3OnChain.circom";

component main{public [requestID,
                       issuerID,
                       issuerClaimIdenState,
                       issuerClaimNonRevState,
                       timestamp,
                       isRevocationChecked,
                       challenge,
                       gistRoot,
                       proofType
                       ]} = credentialAtomicQueryV3OnChain(40, 32, 64, 40, 64);
