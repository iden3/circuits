include "../kyc.circom"

// verifyKYCCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength)
component main = verifyKYCCredentials(4, 17, 16);
