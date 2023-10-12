import { describe } from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;
const chai = require("chai");
const expect = chai.expect;

describe("Test credentialAtomicQueryMTPOffChain.circom", function () {

  this.timeout(600000);

  let circuit;

  before(async () => {
    circuit = await wasmTester(
      path.join(__dirname, "../../circuits", "credentialAtomicQueryMTPV2.circom"),
      {
        output: path.join(__dirname, "circuits", "build"),
        recompile: true,
      },
    );

  });

  after(async () => {
    circuit.release()
  })

  const basePath = '../../testvectorgen/credentials/mtpv2/testdata'
  const tests = [
    require(`${basePath}/claimIssuedOnProfileID.json`),
    require(`${basePath}/claimIssuedOnProfileID2.json`),
    require(`${basePath}/claimIssuedOnUserID.json`),
    require(`${basePath}/claimNonMerklized.json`),
    require(`${basePath}/revoked_claim_without_revocation_check.json`),
  ];

  tests.forEach(({ desc, inputs, expOut }) => {
    it(`${desc}`, async function () {
      const w = await circuit.calculateWitness(inputs, true);
      await circuit.assertOut(w, expOut);
      await circuit.checkConstraints(w);
    });
  });

  const failTestCase = [
    require(`${basePath}/revoked_claim_with_revocation_check.json`),
  ]

  failTestCase.forEach(({ desc, inputs, expOut }) => {
    it(`${desc}`, async function () {
      let error;
      await circuit.calculateWitness(inputs, true).catch((err) => {
        error = err;
      });
      expect(error.message).to.include("Error in template checkClaimNotRevoked");
    })
  });

  it("Checking revoked status when claim is revoked (MTP)", async () => {
    const inputs = {
      "requestID": "23",
      "userGenesisID": "19104853439462320209059061537253618984153217267677512271018416655565783041",
      "profileNonce": "0",
      "claimSubjectProfileNonce": "0",
      "issuerID": "23528770672049181535970744460798517976688641688582489375761566420828291073",
      "issuerClaim": ["3583233690122716044519380227940806650830", "19104853439462320209059061537253618984153217267677512271018416655565783041", "10", "0", "30803922965249841627828060161", "0", "0", "0"],
      "issuerClaimMtp": ["0", "0", "0", "0", "20705360459443886266589173521200199826970601318029396875976898748762842059297", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "issuerClaimClaimsTreeRoot": "4291331108778058814748735252751774985133130667958634779040926608237236193887",
      "issuerClaimRevTreeRoot": "19374975721259875597650302716689543547647001662517455822229477759190533109280",
      "issuerClaimRootsTreeRoot": "0",
      "issuerClaimIdenState": "6344923704725747138709470083565649368088034914458130592289968871891196214095",
      "isRevocationChecked": 1,
      "issuerClaimNonRevClaimsTreeRoot": "4291331108778058814748735252751774985133130667958634779040926608237236193887",
      "issuerClaimNonRevRevTreeRoot": "19374975721259875597650302716689543547647001662517455822229477759190533109280",
      "issuerClaimNonRevRootsTreeRoot": "0",
      "issuerClaimNonRevState": "6344923704725747138709470083565649368088034914458130592289968871891196214095",
      "issuerClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "issuerClaimNonRevMtpAuxHi": "0",
      "issuerClaimNonRevMtpAuxHv": "0",
      "issuerClaimNonRevMtpNoAux": "0",
      "claimSchema": "180410020913331409885634153623124536270",
      "claimPathNotExists": "0",
      "claimPathMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "claimPathMtpNoAux": "0",
      "claimPathMtpAuxHi": "0",
      "claimPathMtpAuxHv": "0",
      "claimPathKey": "0",
      "claimPathValue": "0",
      "operator": 1,
      "slotIndex": 2,
      "timestamp": "1642074362",
      "value": ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]
    };

    let error;
    await circuit.calculateWitness(inputs, true).catch((err) => {
      error = err;
    });
    expect(error.message).to.include("Error in template checkClaimNotRevoked");
  });

});
