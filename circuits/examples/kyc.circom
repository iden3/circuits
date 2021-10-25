pragma circom 2.0.0;

include "../kyc.circom";

// verifyKYCCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength)
component main {public [countryClaimIssuanceIdenState,countryBlacklist,birthdayClaimIssuanceIdenState,currentYear,currentMonth,currentDay,challenge]}= verifyKYCCredentials(4, 40, 16);
