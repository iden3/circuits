import {describe} from "mocha";
import {assert} from "chai";
import { newMemEmptyTrie } from 'circomlibjs'
import { sha256 } from 'js-sha256';
import { generateMRZ } from "../test/utils/passport_mock.test";


const path = require("path");
const wasmTester = require("circom_tester").wasm;

function formatMrz(mrz: string) {
  const mrzCharcodes = [...mrz].map((char) => char.charCodeAt(0));
  mrzCharcodes.unshift(88); // the length of the mrz data
  mrzCharcodes.unshift(95, 31); // the MRZ_INFO_TAG
  mrzCharcodes.unshift(91); // the new length of the whole array
  mrzCharcodes.unshift(97); // the tag for DG1

  return mrzCharcodes;
}

function stringToSHA256(mrz: string): string {
  const mrzByteArray = formatMrz(mrz);
  const unsignedBytesArray = mrzByteArray.map((byte) => byte & 0xff);
  const hexString = sha256(unsignedBytesArray);
  return hexString;
}

async function prepareTestData(mrz: string, lastNameSize: number, firstNameSize: number) {
    const mrzByteArray = formatMrz(mrz);
    if (mrzByteArray.length !== 93) {
      throw new Error("MRZ should be 93 bytes long");
    }

    const treeLevels = 10;
    const tree = await newMemEmptyTrie();
    // key-value pairs to build the credential template
    const template = [
      "4809579517396073186705705159186899409599314609122482090560534255195823961763", "15740774959206304300569618599869272754286189696397051571631518488419809088501", // credentialSubject.type
      "12891444986491254085560597052395677934694594587847693550621945641098238258096", "870222225577550446142292957325790690140780476504858538425256779240825462837", // credentialStatus.type
      "1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962", // credentialSchema.type
      "14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370", // type.id
      "18943208076435454904128050626016920086499867123501959273334294100443438004188", "15740774959206304300569618599869272754286189696397051571631518488419809088501", // type.id
      "2282658739689398501857830040602888548545380116161185117921371325237897538551", "6871229518191218656058751484443257943894148319679406049416377341576591110412", // credentialSchema.id
      "11718818292802126417463134214212976082628052906423225153106612749610200183413", 0, // credentialSubject.dateOfBirth
      "17067102995727523284306589033691644246394899863627321097385336370172459010471", 0, // credentialSubject.documentExpirationDate
      "396948171793807448670779079530437970230319997763427297159364741404168161086", 0, // credentialSubject.firstName
      "1540185022550171417964535586735569210235830901649938832989137234790618138161", 0, // credentialSubject.fullName
      "11665818515976908772146086926627988937767272157525043131077389782866401822622", 0, // credentialSubject.govermentIdentifier
      "20378936560477526294120993552723258097975107008215368308010022877877877266947", 0, // credentialSubject.governmentIdentifierType
      "10966443938224095219566683003147654763133050970169721700346734909387575337367", 0, // credentialSubject.sex
      "1763085948543522232029667616550496120517967703023484347613954302553484294902", 0, // credentialStatus.revocationNonce
      "11896622783611378286548274235251973588039499084629981048616800443645803129554", 0, // credentialStatus.id
      "4792130079462681165428511201253235850015648352883240577315026477780493110675", 0, // credentialSubject.id
      "13483382060079230067188057675928039600565406666878111320562435194759310415773", 0, // expirationDate.id
      "8713837106709436881047310678745516714551061952618778897121563913918335939585", 0, // issuanceDate.id
      "5940025296598751562822259677636111513267244048295724788691376971035167813215", 0, // issuer.id
      "9656117739891539357123771284552289598577388060024608839018723118201732735699", 0, // credentialSubject.nationalities
      "15699466668150257351625206938060640380549592812731019574696943258403707765146", 0, // credentialSubject.nationalities
    ];
    for (let i=0; i<template.length; i+=2) {
      const key = tree.F.e(template[i]);
      const value = tree.F.e(template[i+1]);
      await tree.insert(key, value);
    }
    const templateRoot = tree.F.toObject(tree.root);
  
    const updateTemplate = [
      "11718818292802126417463134214212976082628052906423225153106612749610200183413", "19960309", // credentialSubject.dateOfBirth
      "17067102995727523284306589033691644246394899863627321097385336370172459010471", "20350803", // credentialSubject.documentExpirationDate
      "396948171793807448670779079530437970230319997763427297159364741404168161086", "779590574833975594150553032190316165100034337907701477766077549696170325957", // credentialSubject.firstName
      "1540185022550171417964535586735569210235830901649938832989137234790618138161", "16124395655319932562687594154333620461512120815155591900166934828565073655159", // credentialSubject.fullName
      "11665818515976908772146086926627988937767272157525043131077389782866401822622", "3286800018689036072036595048281161368331306321215602580795106602635276597696", // credentialSubject.govermentIdentifier
      "20378936560477526294120993552723258097975107008215368308010022877877877266947", "12343105779965610540047025345938704312955329035594806470260411576419571786879", // credentialSubject.governmentIdentifierType
      "10966443938224095219566683003147654763133050970169721700346734909387575337367", "4366613503740245542741816499068547859478657796760861141829344679607332353738", // credentialSubject.sex
      "1763085948543522232029667616550496120517967703023484347613954302553484294902", "0", // credentialStatus.revocationNonce
      "11896622783611378286548274235251973588039499084629981048616800443645803129554", "16603911885187767870919822407799731636565604584676607750769528349133273200010", // credentialStatus.id
      "4792130079462681165428511201253235850015648352883240577315026477780493110675", "3745441007954160411654262789843002077789321640339311933900305373126451426785", // credentialSubject.id
      "13483382060079230067188057675928039600565406666878111320562435194759310415773", "2069712000000000000", // expirationDate.id
      "8713837106709436881047310678745516714551061952618778897121563913918335939585", "1742226596000000000", // issuanceDate.id
      "5940025296598751562822259677636111513267244048295724788691376971035167813215", "17295047724547381467021463956538704517040397694116563840254657915956112809540", // issuer.id
      "9656117739891539357123771284552289598577388060024608839018723118201732735699", "14193146200435563417722817655626671239476419932450502386457224894805250323461", // credentialSubject.nationalities
      "15699466668150257351625206938060640380549592812731019574696943258403707765146", "14193146200435563417722817655626671239476419932450502386457224894805250323461", // credentialSubject.nationalities
    ];
    const siblings = [[]];
    for (let i=0; i<updateTemplate.length; i+=2) {
      const key = tree.F.e(updateTemplate[i]);
      const value = tree.F.e(updateTemplate[i+1]);
      const res = await tree.update(key, value);
      for (let i=0; i<res.siblings.length; i++) res.siblings[i] = tree.F.toObject(res.siblings[i]);
      while (res.siblings.length<treeLevels) res.siblings.push(0);
      siblings.push(res.siblings);
    }

    return {
        mrz: [...mrzByteArray],
        lastNameSize: lastNameSize,
        firstNameSize: firstNameSize,
        currentDate: 250401,

        revocationNonce: 0,
        credentialStatusID: "16603911885187767870919822407799731636565604584676607750769528349133273200010",
        credentialSubjectID: "3745441007954160411654262789843002077789321640339311933900305373126451426785",
        userID: "23747161200420134456844951198264139815921171975208487354806063665905574145",
        issuer: "17295047724547381467021463956538704517040397694116563840254657915956112809540",
        issuanceDate: 1742226596,

        templateRoot: templateRoot,
        siblings: siblings,
    }
}

describe("String processor.circom", function() {

  this.timeout(600000);

  let circuit;

  before(async () => {
      circuit = await wasmTester(
          path.join(__dirname, "../circuits/", "extractor.circom"),
          {
              output: path.join(__dirname, "circuits", "build"),
              recompile: true,
              include: [
                path.join(__dirname, '../node_modules'),
              ],
          },
      );

  });

  after(async () => {
      circuit.release()
  })

  it(`Test string processor`, async function() {
    const {mrz, surnameSize, givenNamesSize} = generateMRZ(
      "P",
      "UKR",
      "KUZNETSOV",
      "VALERIY",
      "AC1234567",
      "UKR",
      "960309",
      "M",
      "350803",
    );
    console.log("MRZ: ", mrz);
    const inputs = await prepareTestData(mrz, surnameSize, givenNamesSize);

    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);
    // Document code hash (output 1)
    assert(w[1] === 12343105779965610540047025345938704312955329035594806470260411576419571786879n);

    // Issuing State or organization hash (output 2)
    assert(w[2] === 14193146200435563417722817655626671239476419932450502386457224894805250323461n);

    // Last name hash (output 3)
    assert(w[3] === 16124395655319932562687594154333620461512120815155591900166934828565073655159n);

    // First name hash (output 4)
    assert(w[4] === 779590574833975594150553032190316165100034337907701477766077549696170325957n);

    // Document number hash (output 5)
    assert(w[5] === 3286800018689036072036595048281161368331306321215602580795106602635276597696n);

    // Nationality hash (output 6)
    assert(w[6] === 14193146200435563417722817655626671239476419932450502386457224894805250323461n);

    // Date of Birth hash (output 7)
    assert(w[7] === 19960309n);

    // Sex hash (output 8)
    assert(w[8] === 4366613503740245542741816499068547859478657796760861141829344679607332353738n);

    // Date of expiry hash (output 9)
    assert(w[9] === 20350803n);

    // Hash Index
    assert(w[10] === 8276788121714113194853299279115094498195772456414087292276543151444524599287n);

    // Hash Value
    assert(w[11] === 20661880459224054680311568334655353588113926319608771155576598304028828385849n);
  
    const hashOutputHex = Buffer.from(w.slice(12, 256 / 8 + 12).map(v => Number(v))).toString('hex');
    assert(hashOutputHex === stringToSHA256(mrz), `Hash output is not correct: ${hashOutputHex}`);
  });
  /*
  it(`Double last name`, async function() {
    const {mrz, surnameSize, givenNamesSize} = generateMRZ(
      "P",
      "UKR",
      "KUZNETSOV",
      "VALERIY",
      "AC1234567",
      "UKR",
      "960309",
      "M",
      "350803",
    );
    const inputs = await prepareTestData(docs, 11, 8);
    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);
    // Document code hash (output 1)
    assert(w[1] === 12343105779965610540047025345938704312955329035594806470260411576419571786879n);

    // Issuing State or organization hash (output 2)
    assert(w[2] === 14193146200435563417722817655626671239476419932450502386457224894805250323461n);

    // Last name hash (output 3)
    assert(w[3] === 16684418381729930583844995012712504418990732401801825107387099797112025696324n);

    // First name hash (output 4)
    assert(w[4] === 7882444430312531813986531690355256034187461560449276183886474511877560234822n);

    // Document number hash (output 5)
    assert(w[5] === 13365184592845315309100297120259965838903705444844448460767566282483182375642n);

    // Nationality hash (output 6)
    assert(w[6] === 14193146200435563417722817655626671239476419932450502386457224894805250323461n);

    // Date of Birth hash (output 7)
    assert(w[7] === 19980309n);

    // Sex hash (output 8)
    assert(w[8] === 4366613503740245542741816499068547859478657796760861141829344679607332353738n);

    // Date of expiry hash (output 9)
    assert(w[9] === 20310803n);
  });
  */
  it(`Passport is expired`, async function() {
    const {mrz, surnameSize, givenNamesSize} = generateMRZ(
      "P",
      "UKR",
      "KUZNETSOV",
      "VALERIY",
      "AC1234567",
      "UKR",
      "960309",
      "M",
      "210803",
    );
    const inputs = await prepareTestData(mrz, surnameSize, givenNamesSize);
    try {
      await circuit.calculateWitness(inputs, true);
      assert.fail("Expected an Assertion Error but no error was thrown");
    } catch (error) {
      assert(error.message.includes("Assert Failed"), 
        `Expected Assertion Error but got: ${error.message}`);
    }
  });
});

function bigintToUtf8(big: bigint): string {
    let hex = big.toString(16);
    
    if (hex.length % 2 !== 0) {
      hex = '0' + hex;
    }
    
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

function bigIntChunksToByteArray(
    bigIntChunks: bigint[],
    bytesPerChunk = 31,
  ) {
    const bytes: number[] = []
  
    // Remove last chunks that are 0n
    const cleanChunks = bigIntChunks
      .reduce(
        (acc: bigint[], item) =>
          acc.length || item !== 0n ? [...acc, item] : [],
        [],
      )
  
    cleanChunks.forEach((bigInt, i) => {
      let byteCount = 0
  
      while (bigInt > 0n) {
        bytes.unshift(Number(bigInt & 0xffn))
        bigInt >>= 8n
        byteCount++
      }
  
      // Except for the last chunk, each chunk should be of size bytesPerChunk
      // This will add 0s that were removed during the conversion because they are LSB
      if (i < cleanChunks.length - 1) {
        if (byteCount < bytesPerChunk) {
          for (let j = 0; j < bytesPerChunk - byteCount; j++) {
            bytes.unshift(0)
          }
        }
      }
    })
  
    return bytes
  }

function bigIntsToString(bigIntChunks: bigint[]) {
    return bigIntChunksToByteArray(bigIntChunks)
      .map(byte => String.fromCharCode(byte))
      .join('')
  }