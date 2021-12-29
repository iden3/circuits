pragma circom 2.0.0;

include "credential.circom";
include "ageCalculation.circom";


// verifyKYCCredentials proves ownership and validity of Country of Residence Claim
// and Birthday Claim and verifies they have allowed values (age >= 18 and country
// in not in the blacklist)
template verifyKYCCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength) {

    /* id ownership signals */
	signal input id;
	signal input userPrivateKey;
	signal input BBJClaimMtp[IdOwnershipLevels];
	signal input BBJClaimClaimsTreeRoot;
	// signal input BBJClaimRevTreeRoot;
	// signal input BBJClaimRootsTreeRoot;

    /* country claim signals */
	signal input countryClaim[8];
	signal input countryClaimIssuanceMtp[IssuerLevels];
	signal input countryClaimIssuanceClaimsTreeRoot;
	signal input countryClaimIssuanceRevTreeRoot;
	signal input countryClaimIssuanceRootsTreeRoot;
	signal input countryClaimIssuanceIdenState;

    signal input countryBlacklist[CountryBlacklistLength];

    signal input countryClaimNonRevMtp[IssuerLevels];
    signal input countryClaimNonRevMtpNoAux;
    signal input countryClaimNonRevMtpAuxHi;
    signal input countryClaimNonRevMtpAuxHv;
    signal input countryClaimNonRevIssuerState;
    signal input countryClaimNonRevIssuerClaimsTreeRoot;
    signal input countryClaimNonRevIssuerRevTreeRoot;
    signal input countryClaimNonRevIssuerRootsTreeRoot;

    /* birthday claim signals */
	signal input birthdayClaim[8];
	signal input birthdayClaimIssuanceMtp[IssuerLevels];
	signal input birthdayClaimIssuanceClaimsTreeRoot;
	signal input birthdayClaimIssuanceRevTreeRoot;
	signal input birthdayClaimIssuanceRootsTreeRoot;
	signal input birthdayClaimIssuanceIdenState;

    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal input minAge;

    signal input challenge;

    signal input birthdayClaimNonRevMtp[IssuerLevels];
    signal input birthdayClaimNonRevMtpNoAux;
    signal input birthdayClaimNonRevMtpAuxHi;
    signal input birthdayClaimNonRevMtpAuxHv;
    signal input birthdayClaimNonRevIssuerState;
    signal input birthdayClaimNonRevIssuerClaimsTreeRoot;
    signal input birthdayClaimNonRevIssuerRevTreeRoot;
    signal input birthdayClaimNonRevIssuerRootsTreeRoot;
    /*
        Id ownership check
    */
    // TODO: switch to IdOwnership template
    component userIdOwnership = IdOwnershipGenesis(IdOwnershipLevels);
    userIdOwnership.id <== id;
    userIdOwnership.userPrivateKey <== userPrivateKey;
    for (var i=0; i<IdOwnershipLevels; i++) { userIdOwnership.siblings[i] <== BBJClaimMtp[i]; }
    userIdOwnership.claimsTreeRoot <== BBJClaimClaimsTreeRoot;

    /*
        Country claim checks
    */
    // check country claim is issued to provided identity
    component countryClaimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { countryClaimIdCheck.claim[i] <== countryClaim[i]; }
    countryClaimIdCheck.id <== id;

    // TODO: add schema check

    component verifyCountryClaimIssuance = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { verifyCountryClaimIssuance.claim[i] <== countryClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyCountryClaimIssuance.claimIssuanceMtp[i] <== countryClaimIssuanceMtp[i]; }
    verifyCountryClaimIssuance.claimIssuanceClaimsTreeRoot <== countryClaimIssuanceClaimsTreeRoot;
    verifyCountryClaimIssuance.claimIssuanceRevTreeRoot <== countryClaimIssuanceRevTreeRoot;
    verifyCountryClaimIssuance.claimIssuanceRootsTreeRoot <== countryClaimIssuanceRootsTreeRoot;
    verifyCountryClaimIssuance.claimIssuanceIdenState <== countryClaimIssuanceIdenState;

    for (var i=0; i<IssuerLevels; i++) {
        verifyCountryClaimIssuance.claimNonRevMtp[i] <== countryClaimNonRevMtp[i];
    }
    verifyCountryClaimIssuance.claimNonRevMtpNoAux <== countryClaimNonRevMtpNoAux;
    verifyCountryClaimIssuance.claimNonRevMtpAuxHi <== countryClaimNonRevMtpAuxHi;
    verifyCountryClaimIssuance.claimNonRevMtpAuxHv <== countryClaimNonRevMtpAuxHv;
    verifyCountryClaimIssuance.claimNonRevIssuerClaimsTreeRoot <== countryClaimNonRevIssuerClaimsTreeRoot;
    verifyCountryClaimIssuance.claimNonRevIssuerRevTreeRoot <== countryClaimNonRevIssuerRevTreeRoot;
    verifyCountryClaimIssuance.claimNonRevIssuerRootsTreeRoot <== countryClaimNonRevIssuerRootsTreeRoot;
    verifyCountryClaimIssuance.claimNonRevIssuerState <== countryClaimNonRevIssuerState;

    // get country value
    component country = getCountry();
    for (var i=0; i<8; i++) { country.claim[i] <== countryClaim[i]; }
    //country.country === 31
    component eq[CountryBlacklistLength];
    for (var i=0; i<CountryBlacklistLength; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== country.country;
        eq[i].in[1] <== countryBlacklist[i];
        eq[i].out === 0;
    }

    /*
        Birthday claim checks
    */
    // check birthday claim is issued to provided identity
    component birthdayClaimIdCheck = verifyCredentialSubject();
    for (var i=0; i<8; i++) { birthdayClaimIdCheck.claim[i] <== birthdayClaim[i]; }
    birthdayClaimIdCheck.id <== id;

    // TODO: add schema check

    component verifyBirthdayClaimIssuance = verifyClaimIssuanceNonRev(IssuerLevels);
    for (var i=0; i<8; i++) { verifyBirthdayClaimIssuance.claim[i] <== birthdayClaim[i]; }
    for (var i=0; i<IssuerLevels; i++) { verifyBirthdayClaimIssuance.claimIssuanceMtp[i] <== birthdayClaimIssuanceMtp[i]; }
    verifyBirthdayClaimIssuance.claimIssuanceClaimsTreeRoot <== birthdayClaimIssuanceClaimsTreeRoot;
    verifyBirthdayClaimIssuance.claimIssuanceRevTreeRoot <== birthdayClaimIssuanceRevTreeRoot;
    verifyBirthdayClaimIssuance.claimIssuanceRootsTreeRoot <== birthdayClaimIssuanceRootsTreeRoot;
    verifyBirthdayClaimIssuance.claimIssuanceIdenState <== birthdayClaimIssuanceIdenState;
    for (var i=0; i<IssuerLevels; i++) {
        verifyBirthdayClaimIssuance.claimNonRevMtp[i] <== birthdayClaimNonRevMtp[i];
    }
    verifyBirthdayClaimIssuance.claimNonRevMtpNoAux <== birthdayClaimNonRevMtpNoAux;
    verifyBirthdayClaimIssuance.claimNonRevMtpAuxHi <== birthdayClaimNonRevMtpAuxHi;
    verifyBirthdayClaimIssuance.claimNonRevMtpAuxHv <== birthdayClaimNonRevMtpAuxHv;
    verifyBirthdayClaimIssuance.claimNonRevIssuerClaimsTreeRoot <== birthdayClaimNonRevIssuerClaimsTreeRoot;
    verifyBirthdayClaimIssuance.claimNonRevIssuerRevTreeRoot <== birthdayClaimNonRevIssuerRevTreeRoot;
    verifyBirthdayClaimIssuance.claimNonRevIssuerRootsTreeRoot <== birthdayClaimNonRevIssuerRootsTreeRoot;
    verifyBirthdayClaimIssuance.claimNonRevIssuerState <== birthdayClaimNonRevIssuerState;


    // get birthday value
    component getBirthdayField = getBirthdayField();
    for (var i=0; i<8; i++) { getBirthdayField.claim[i] <== birthdayClaim[i]; }

    // calculate age
	component age = calculateAgeFromYYYYMMDD();
	age.yyyymmdd <== getBirthdayField.birthday;
	age.currentYear <== currentYear;
	age.currentMonth <== currentMonth;
	age.currentDay <== currentDay;

    // verify age > minAge
    component gte18 = GreaterEqThan(32);
    gte18.in[0] <== age.age;
    gte18.in[1] <== minAge;
    gte18.out === 1;

}
// getBirthday gets the country from a country claim
template getCountry() {
	signal input claim[8];
	signal output country;

 	component i2 = Num2Bits(253);
	i2.in <== claim[2];

	component num = Bits2Num(32);

    // copy 32 bits starting from position 0
	for (var i=0; i<32; i++) {
		num.in[i] <== i2.out[i];
	}
	country <== num.out;
}

// getBirthdayField gets the birthday from a birthday claim
template getBirthdayField() {
	signal input claim[8];
	signal output birthday;

 	component i2 = Num2Bits(253);
	i2.in <== claim[2];

	component num = Bits2Num(32);

    // copy 32 bits starting from position 0
    for (var i=0; i<32; i++) {
    	num.in[i] <== i2.out[i];
    }
    birthday <== num.out;
}
