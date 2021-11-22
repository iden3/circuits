include "credential.circom"

// verifyKYCCredentials proves ownership and validity of Country of Residence Claim
// and Birthday Claim and verifies they have allowed values (age >= 18 and country
// in not in the blacklist)
template verifyKYCCredentials(IdOwnershipLevels, IssuerLevels, CountryBlacklistLength) {

    /* id ownership signals */
	signal input id;
	signal private input userPrivateKey;
	signal private input BBJClaimMtp[IdOwnershipLevels];
	signal private input BBJClaimClaimsTreeRoot;
	// signal private input BBJClaimRevTreeRoot;
	// signal private input BBJClaimRootsTreeRoot;

    /* country claim signals */
	signal private input countryClaim[8];
	signal private input countryClaimIssuanceMtp[IssuerLevels];
	signal private input countryClaimIssuanceClaimsTreeRoot;
	signal private input countryClaimIssuanceRevTreeRoot;
	signal private input countryClaimIssuanceRootsTreeRoot;
	signal input countryClaimIssuanceIdenState;

    signal input countryBlacklist[CountryBlacklistLength]

    signal private input countryClaimNonRevMtp[IssuerLevels];
    signal private input countryClaimNonRevMtpNoAux;
    signal private input countryClaimNonRevMtpAuxHi;
    signal private input countryClaimNonRevMtpAuxHv;
    signal input countryClaimNonRevIssuerState;
    signal private input countryClaimNonRevIssuerClaimsTreeRoot;
    signal private input countryClaimNonRevIssuerRevTreeRoot;
    signal private input countryClaimNonRevIssuerRootsTreeRoot;

    /* birthday claim signals */
	signal private input birthdayClaim[8];
	signal private input birthdayClaimIssuanceMtp[IssuerLevels];
	signal private input birthdayClaimIssuanceClaimsTreeRoot;
	signal private input birthdayClaimIssuanceRevTreeRoot;
	signal private input birthdayClaimIssuanceRootsTreeRoot;
	signal input birthdayClaimIssuanceIdenState;

    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;

    signal input minAge;

    signal input challenge;

    signal private input birthdayClaimNonRevMtp[IssuerLevels];
    signal private input birthdayClaimNonRevMtpNoAux;
    signal private input birthdayClaimNonRevMtpAuxHi;
    signal private input birthdayClaimNonRevMtpAuxHv;
    signal input birthdayClaimNonRevIssuerState;
    signal private input birthdayClaimNonRevIssuerClaimsTreeRoot;
    signal private input birthdayClaimNonRevIssuerRevTreeRoot;
    signal private input birthdayClaimNonRevIssuerRootsTreeRoot;
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
        eq[i] = IsEqual()
        eq[i].in[0] <== country.country
        eq[i].in[1] <== countryBlacklist[i]
        eq[i].out === 0
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
    component birthday = getBirthday();
    for (var i=0; i<8; i++) { birthday.claim[i] <== birthdayClaim[i]; }
//
//    // calculate age
	component age = calculateAge();
	age.DOBYear <== birthday.year;
	age.DOBMonth <== birthday.month;
	age.DOBDay <== birthday.day;
	age.CurYear <== currentYear;
	age.CurMonth <== currentMonth;
	age.CurDay <== currentDay;

//    component age = getAge();
//    for (var i=0; i<8; i++) { age.claim[i] <== birthdayClaim[i]; }

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

// getBirthday gets the country from a country claim
template getBirthday() {
	signal input claim[8];
	signal output year;
	signal output month;
	signal output day;

 	component i2 = Num2Bits(253);
	i2.in <== claim[2];

	component numY = Bits2Num(32);

    // copy 32 bits starting from position 0
	for (var i=0; i<32; i++) {
		numY.in[i] <== i2.out[i+0];
	}
	year <== numY.out;
	
	component numM = Bits2Num(32);

    // copy 32 bits starting from position 32
	for (var i=0; i<32; i++) {
		numM.in[i] <== i2.out[i+32];
	}
	month <== numM.out;
	
	component numD = Bits2Num(32);

    // copy 32 bits starting from position 64
	for (var i=0; i<32; i++) {
		numD.in[i] <== i2.out[i+64];
	}
	day <== numD.out;
}

// getAge gets age from an age claim
template getAge() {
	signal input claim[8];
	signal output age;

 	component i2 = Num2Bits(253);
	i2.in <== claim[2];

	component numY = Bits2Num(32);

    // copy 32 bits starting from position 0
	for (var i=0; i<32; i++) {
		numY.in[i] <== i2.out[i];
	}
	age <== numY.out;
}

template calculateAge() {
	signal input DOBYear;
	signal input DOBMonth;
	signal input DOBDay;
	signal input CurYear;
	signal input CurMonth;
	signal input CurDay;
	signal output age;

    component validDOB = validateDate();
    validDOB.year <== DOBYear;
    validDOB.month <== DOBMonth;
    validDOB.day <== DOBDay;

    component validCurDate = validateDate();
    validCurDate.year <== CurYear;
    validCurDate.month <== CurMonth;
    validCurDate.day <== CurDay;

    component gteY = GreaterEqThan(32)
    gteY.in[0] <== CurYear;
    gteY.in[1] <== DOBYear;
    gteY.out === 1;

    var yearDiff = CurYear - DOBYear;

    component ltM = LessThan(32);
    ltM.in[0] <== CurMonth * 100 + CurDay;
    ltM.in[1] <== DOBMonth * 100 + DOBDay;

    component gte0 = GreaterEqThan(32);
    gte0.in[0] <== yearDiff - ltM.out;
    gte0.in[1] <== 0;
    gte0.out === 1;

    age <== yearDiff - ltM.out;
}

template validateDate() {
    signal input year;
    signal input month;
    signal input day;

    component yearGte1900 = GreaterEqThan(32);
    yearGte1900.in[0] <== year;
    yearGte1900.in[1] <== 1900;
    yearGte1900.out === 1;

    component yearLte2100 = LessEqThan(32);
    yearLte2100.in[0] <== year;
    yearLte2100.in[1] <== 2100;
    yearLte2100.out === 1;

    component monthGte1 = GreaterEqThan(32);
    monthGte1.in[0] <== month;
    monthGte1.in[1] <== 1;
    monthGte1.out === 1;

    component monthLte12 = LessEqThan(32);
    monthLte12.in[0] <== month;
    monthLte12.in[1] <== 12;
    monthLte12.out === 1;

    component dayGte1 = GreaterEqThan(32);
    dayGte1.in[0] <== day;
    dayGte1.in[1] <== 1;
    dayGte1.out === 1;

    component dayLte31 = LessEqThan(32);
    dayLte31.in[0] <== day;
    dayLte31.in[1] <== 31;
    dayLte31.out === 1;
}
