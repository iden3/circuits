pragma circom 2.0.0;

include "../query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        id,
                        hoIdenState,
                        issuerID,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQueryMTP(40, 40, 16);
