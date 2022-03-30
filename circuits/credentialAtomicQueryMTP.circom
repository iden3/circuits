pragma circom 2.0.0;

include "lib/query/credentialAtomicQueryMTP.circom";

component main{public [challenge,
                        id,
                        hoIdenState,
                        issuerID,
                        claimIssuanceIdenState,
                        claimSchema,
                        slotIndex,
                        operator,
                        value,
                        timestamp]} = CredentialAtomicQueryMTP(40, 40, 16);
