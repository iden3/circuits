pragma circom 2.0.0;

include "./bytes.circom";
include "./constants.circom";
include "./dateUtils/simpleNormalize.circom";
include "./toTimestamp.circom";
include "./claimBuilder.circom";
include "./claimV0Builder.circom";
include "./hasher/hash.circom";
include "./bitify/bytes.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "@openpassport/zk-email-circuits/utils/array.circom";

template PaddingAndPoseidon(fieldSize) {
    signal input in[fieldSize];
    signal output hash;

    component outInts = PackBytes(messageMaxSize());
    for (var i = 0; i < fieldSize; i ++) {
        outInts.in[i] <== in[i];
    }
    // padding
    for (var i = fieldSize; i < messageMaxSize(); i++) {
        outInts.in[i] <== 0;
    }
    
    component poseidon = Poseidon(chunkCount());
    poseidon.inputs <== outInts.out;
    hash <== poseidon.out;
}

template Extractor(mrzSize, shift, fieldSize) {
    signal input mrz[mrzSize];
    signal output hash;

    signal field[fieldSize];
    component eq[fieldSize];
    // TODO (illia-korotia): we can rewrite this for to separate template
    // and pass from symbol to symbol
    for (var i = 0; i < fieldSize; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== mrz[shift + i];
        eq[i].in[1] <== mrzDelimiterSymbol();
        field[i] <== (1 - eq[i].out) * mrz[shift + i];
    }

    component pap = PaddingAndPoseidon(fieldSize);
    pap.in <== field;
    hash <== pap.hash;
}

template ExtractorDate(mrzSize, shift, fieldSize) {
    signal input mrz[mrzSize];
    signal input currentDate;
    
    signal output out;

    signal field[fieldSize];
    component eq[fieldSize];
    // TODO (illia-korotia): we can rewrite this for to separate template
    // and pass from symbol to symbol
    for (var i = 0; i < fieldSize; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== mrz[shift + i];
        eq[i].in[1] <== mrzDelimiterSymbol();
        field[i] <== (1 - eq[i].out) * mrz[shift + i];
    }

    component dateInt = DigitBytesToInt(fieldSize);
    dateInt.in <== field;

    component converter = DateFormatConverter();
    converter.date <== dateInt.out;
    converter.currentDate <== currentDate;

    // we don't use poseidon for ints
    out <== converter.formattedDate;
}

template ExtractorDOE(mrzSize, shift, fieldSize) {
    signal input mrz[mrzSize];    
    signal input currentDate;

    signal output out;
    signal output timestamp;

    signal field[fieldSize];
    component eq[fieldSize];
    // TODO (illia-korotia): we can rewrite this for to separate template
    // and pass from symbol to symbol
    for (var i = 0; i < fieldSize; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== mrz[shift + i];
        eq[i].in[1] <== mrzDelimiterSymbol();
        field[i] <== (1 - eq[i].out) * mrz[shift + i];
    }

    component dateInt = DigitBytesToInt(fieldSize);
    dateInt.in <== field;

    signal lt <== LessEqThan(64)([currentDate, dateInt.out]);
    lt === 1;

    out <== 20000000 + dateInt.out;

    signal output year <== DigitBytesToInt(2)([field[0], field[1]]);
    signal output month <== DigitBytesToInt(2)([field[2], field[3]]);
    signal output day <== DigitBytesToInt(2)([field[4], field[5]]);

    component dateToUnixTime = DigitBytesToTimestamp(2100);
    dateToUnixTime.year <== 2000 + year;
    dateToUnixTime.month <== month;
    dateToUnixTime.day <== day;
    dateToUnixTime.hour <== 0;
    dateToUnixTime.minute <== 0;
    dateToUnixTime.second <== 0;

    timestamp <== dateToUnixTime.out;
}

template ExtractorHolder(mrzSize) {
    signal input mrz[mrzSize];
    signal input start;
    signal input end;

    signal output hash;
    
    component selector = SelectSubArray(mrzSize, nameOfHolderSize());
    selector.in <== mrz;
    selector.startIndex <== start;
    selector.length <== end;
    signal subArray[nameOfHolderSize()] <== selector.out;

    signal normalizedHolder[nameOfHolderSize()];
    component eq[nameOfHolderSize()];
    for (var i = 0; i < nameOfHolderSize(); i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== subArray[i];
        eq[i].in[1] <== mrzDelimiterSymbol();
        
        // Calculate output: if character is '<', replace with space, otherwise keep the character
        normalizedHolder[i] <== spaceSymbol() * eq[i].out + subArray[i] * (1 - eq[i].out);
    }

   component pap = PaddingAndPoseidon(nameOfHolderSize());
   pap.in <== normalizedHolder;
   hash <== pap.hash;
}

/*
    The template MRZFieldExtractor cuts fields as from MRZ:
    1. Document code: Position 1, Size 2
    2. Issuing State or organization: Position 3, Size 3
    3. Name of holder: Position 6, Size 39
    4. Document number: Position 1, Size 9
    5. Nationality: Position 11, Size 3
    6. DOB: Position 14, Size 6
    7. Sex: Position 21, Size 1
    8. Date of expiry: Position 22, Size 6
*/
template MRZFieldExtractor(DgHashAlg, nLevels, smtChanges) {
    signal input mrz[MZR_TD3_SIZE()];
    signal input lastNameSize;
    signal input firstNameSize;
    signal input currentDate; // TODO (illia-korotia): Is field should be public input? Format: YYMMDD

    signal input revocationNonce;
    signal input credentialStatusID;
    signal input credentialSubjectID;
    signal input userID;
    signal input issuer;
    signal input issuanceDate;


    signal input templateRoot;
    signal input siblings[smtChanges][nLevels];

    signal output documentCodeHash;
    signal output documentIssuerHash;
    signal output documentLastNameHash;
    signal output documentFirstNameHash;
    signal output documentNumberHash;
    signal output documentNationalityHash;
    signal output documentDOB;
    signal output documentSexHash;
    signal output documentDOE;
    signal output hashIndex;
    signal output hashValue;
    // signal output dg1Hash;


    component documentCodeExtractor = Extractor(MZR_TD3_SIZE(), documentCodePosition(), documentCodeSize());
    documentCodeExtractor.mrz <== mrz;
    documentCodeHash <== documentCodeExtractor.hash;

    component documentIssuerExtractor = Extractor(MZR_TD3_SIZE(), issuingStatePosition(), issuingStateSize());
    documentIssuerExtractor.mrz <== mrz;
    documentIssuerHash <== documentIssuerExtractor.hash;

    component lastNameExtractor = ExtractorHolder(MZR_TD3_SIZE());
    lastNameExtractor.mrz <== mrz;
    lastNameExtractor.start <== nameOfHolderPosition();
    lastNameExtractor.end <== lastNameSize;
    documentLastNameHash <== lastNameExtractor.hash;

    component firstNameExtractor = ExtractorHolder(MZR_TD3_SIZE());
    firstNameExtractor.mrz <== mrz;
    firstNameExtractor.start <== nameOfHolderPosition() + lastNameSize + 2;
    firstNameExtractor.end <== firstNameSize;
    documentFirstNameHash <== firstNameExtractor.hash;

    component documentNumberExtractor = Extractor(MZR_TD3_SIZE(), documentNumberPosition(), documentNumberSize());
    documentNumberExtractor.mrz <== mrz;
    documentNumberHash <== documentNumberExtractor.hash;

    component documentNationalityExtractor = Extractor(MZR_TD3_SIZE(), nationalityPosition(), nationalitySize());
    documentNationalityExtractor.mrz <== mrz;
    documentNationalityHash <== documentNationalityExtractor.hash;

    component documentDOBExtractor = ExtractorDate(MZR_TD3_SIZE(), dobPosition(), dobSize());
    documentDOBExtractor.mrz <== mrz;
    documentDOBExtractor.currentDate <== currentDate;
    documentDOB <== documentDOBExtractor.out;

    component documentSexExtractor = Extractor(MZR_TD3_SIZE(), sexPosition(), sexSize());
    documentSexExtractor.mrz <== mrz;
    documentSexHash <== documentSexExtractor.hash;

    component documentDOEExtractor = ExtractorDOE(MZR_TD3_SIZE(), dateOfExpiryPosition(), dateOfExpirySize());
    documentDOEExtractor.mrz <== mrz;
    documentDOEExtractor.currentDate <== currentDate;
    documentDOE <== documentDOEExtractor.out;
    signal documentDOETimestamp <== documentDOEExtractor.timestamp;


    // TODO (illia-korotia): move to separate circuit:
    var keysToUpdate[smtChanges] = [
        11718818292802126417463134214212976082628052906423225153106612749610200183413, // credentialSubject.dateOfBirth
        17067102995727523284306589033691644246394899863627321097385336370172459010471, // credentialSubject.documentExpirationDate
        396948171793807448670779079530437970230319997763427297159364741404168161086, // credentialSubject.firstName
        1540185022550171417964535586735569210235830901649938832989137234790618138161, // credentialSubject.fullName
        11665818515976908772146086926627988937767272157525043131077389782866401822622, // credentialSubject.govermentIdentifier
        20378936560477526294120993552723258097975107008215368308010022877877877266947, // credentialSubject.governmentIdentifierType
        10966443938224095219566683003147654763133050970169721700346734909387575337367, // credentialSubject.sex
        1763085948543522232029667616550496120517967703023484347613954302553484294902, // credentialStatus.revocationNonce
        11896622783611378286548274235251973588039499084629981048616800443645803129554, // credentialStatus.id
        4792130079462681165428511201253235850015648352883240577315026477780493110675, // credentialSubject.id
        13483382060079230067188057675928039600565406666878111320562435194759310415773, // expirationDate.id
        8713837106709436881047310678745516714551061952618778897121563913918335939585, // issuanceDate.id
        5940025296598751562822259677636111513267244048295724788691376971035167813215, // issuer.id
        9656117739891539357123771284552289598577388060024608839018723118201732735699, // credentialSubject.nationalities
        15699466668150257351625206938060640380549592812731019574696943258403707765146 // credentialSubject.nationalities
    ];

    // For debuging mt update
    log(documentDOB);
    log(documentDOE);
    log(documentFirstNameHash);
    log(documentLastNameHash);
    log(documentNumberHash);
    log(documentCodeHash);
    log(documentSexHash);
    log(revocationNonce);
    log(credentialStatusID);
    log(credentialSubjectID);
    log(documentDOETimestamp * 1000000000);
    log(issuanceDate * 1000000000);
    log(issuer);
    log(documentNationalityHash);
    log(documentIssuerHash);

    var valuesToUpdate[smtChanges] = [
        documentDOB, // credentialSubject.dateOfBirth
        documentDOE, // credentialSubject.documentExpirationDate
        documentFirstNameHash, // credentialSubject.firstName
        documentLastNameHash, // credentialSubject.fullName
        documentNumberHash, // credentialSubject.govermentIdentifier
        documentCodeHash, // credentialSubject.governmentIdentifierType
        documentSexHash, // credentialSubject.sex
        revocationNonce, // credentialStatus.revocationNonce (placeholder value)
        credentialStatusID, // credentialStatus.id (placeholder value)
        credentialSubjectID, // credentialSubject.id (placeholder value)
        documentDOETimestamp * 1000000000, // expirationDate.id (placeholder value)
        issuanceDate * 1000000000, // issuanceDate.id (placeholder value)
        issuer, // issuer.id (placeholder value)
        documentNationalityHash, // credentialSubject.nationalities
        documentIssuerHash // credentialSubject.nationalities (duplicate entry)
    ];

    component c = ClaimRootBuilder(nLevels, smtChanges);
    c.templateRoot <== templateRoot;
    c.siblings <== siblings;
    c.keys <== keysToUpdate;
    c.values <== valuesToUpdate;

    // For debuging mt root
    log(c.newRoot);

    // The value was calculated using the go-iden3-core library
    var i0 = v0();
    component hI = Poseidon(4);
    hI.inputs[0] <== i0;
    hI.inputs[1] <== userID;
    hI.inputs[2] <== c.newRoot;
    hI.inputs[3] <== 0;

    component V0Calc = V0Calculator();
    V0Calc.revocation <== revocationNonce;
    V0Calc.expiration <== documentDOETimestamp;

    component hV = Poseidon(4);
    hV.inputs[0] <== V0Calc.out;
    hV.inputs[1] <== 0;
    hV.inputs[2] <== 0;
    hV.inputs[3] <== 0;

    hashIndex <== hI.out;
    hashValue <== hV.out;

    var hashAlgBytesSize = DgHashAlg / 8;
    signal output dg1ShaBytes[hashAlgBytesSize];
    signal dg1Bits[MZR_TD3_SIZE_BITS()] <== BytesToBitsArray(MZR_TD3_SIZE())(mrz);
    signal dg1ShaBits[DgHashAlg] <== ShaHashBits(MZR_TD3_SIZE_BITS(), DgHashAlg)(dg1Bits);
    dg1ShaBytes <== BitsToBytesArray(DgHashAlg)(dg1ShaBits);
    // dg1Hash <== DigitBytesToInt(hashAlgBytesSize)(dg1ShaBytes);
}

component main { public [templateRoot, issuanceDate] } = MRZFieldExtractor(256, 10, 15);
