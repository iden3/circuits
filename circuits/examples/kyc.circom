pragma circom 2.0.0;

include "../kyc.circom";

// verifyKYCCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength)
component main {public [
    id,
    countryClaimIssuanceIdenState,
    countryBlacklist,
    countryClaimNonRevIssuerState,
    birthdayClaimIssuanceIdenState,
    birthdayClaimNonRevIssuerState,
    currentYear,
    currentMonth,
    currentDay,
    minAge,
    challenge
]}= verifyKYCCredentials(4, 40, 16);
