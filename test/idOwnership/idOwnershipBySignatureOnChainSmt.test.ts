const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("idOwnershipBySignature", function () {
  this.timeout(600000);

  let circuit;

  before(async () => {
    circuit = await tester(
      path.join(__dirname, "../circuits", "idOwnershipBySignatureOnChainSmtTest.circom"),
      {
        output: path.join(__dirname, "../circuits", "build/idOwnershipBySignatureOnChainSmt"),
        recompile: true,
        reduceConstraints: false,
      },
    );
  });

  it("Ownership true. User state: genesis. Auth claims total/signedWith/revoked: 1/1/none", async () => {
    const inputs = {
      "challenge": "1",
      "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449",
      "challengeSignatureR8y": "5507837342589329113352496188906367161790372084365285966741761856353367255709",
      "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655",
      "nullifierHash": "3886931623570934357017887171328389254245198238824798786420210009480671968146",
      "userAuthClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
      "userAuthClaimMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userAuthClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userAuthClaimNonRevMtpAuxHi": "0",
      "userAuthClaimNonRevMtpAuxHv": "0",
      "userAuthClaimNonRevMtpNoAux": "1",
      "userClaimsTreeRoot": "9763429684850732628215303952870004997159843236039795272605841029866455670219",
      "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272",
      "userRevTreeRoot": "0",
      "userRootsTreeRoot": "0",
      "userState": "18656147546666944484453899241916469544090258810192803949522794490493271005313",
      "userStateInOnChainSmtMtp": ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userStateInOnChainSmtMtpAuxHi": "4",
      "userStateInOnChainSmtMtpAuxHv": "300",
      "userStateInOnChainSmtMtpNoAux": "0",
      "userStateInOnChainSmtRoot": "2960269998131412406135915396987536312795307713692807443361231572350088373156",
      "verifierCorrelationID": "123456789",
    }

    const witness = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(witness);
  });

  it("Ownership true. User state: not-genesis. Auth claims total/signedWith/revoked: 1/1/none", async () => {
    const inputs = {
      "challenge": "1",
      "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449",
      "challengeSignatureR8y": "5507837342589329113352496188906367161790372084365285966741761856353367255709",
      "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655",
      "nullifierHash": "3886931623570934357017887171328389254245198238824798786420210009480671968146",
      "userAuthClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
      "userAuthClaimMtp": ["0", "0", "1243904711429961858774220647610724273798918457991486031567244100767259239747", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userAuthClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userAuthClaimNonRevMtpAuxHi": "0",
      "userAuthClaimNonRevMtpAuxHv": "0",
      "userAuthClaimNonRevMtpNoAux": "1",
      "userClaimsTreeRoot": "3325296375493109531775738970103865437471502880293182874312109748701010548081",
      "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272",
      "userRevTreeRoot": "0",
      "userRootsTreeRoot": "0",
      "userState": "21556156816336611928260850205358242317673071374695788694657164635542250181506",
      "userStateInOnChainSmtMtp": ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "19991091798052235227442886829713443191817461077589875647331508266325270343516", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userStateInOnChainSmtMtpAuxHi": "0",
      "userStateInOnChainSmtMtpAuxHv": "0",
      "userStateInOnChainSmtMtpNoAux": "0",
      "userStateInOnChainSmtRoot": "2527369248886058159298190241228260543545233125629989424050431010562778308348",
      "verifierCorrelationID": "123456789",
    }

    const witness = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(witness);
  });

  it("Ownership true. User state: not-genesis. Auth claims total/signedWith/revoked: 2/2/none", async () => {
    const inputs = {
      "challenge": "1",
      "challengeSignatureR8x": "3318605682427930847043923964996627571509054270532204838981931388121839601904",
      "challengeSignatureR8y": "6885828942356963641443098413925008636428756893590364657052219244852107012379",
      "challengeSignatureS": "1239257276045842588253148642684748186882810960469506371777432113478495615573",
      "nullifierHash": "1958873713344339126643835800912906153736137480363386060715177511808049651739",
      "userAuthClaim": ["304427537360709784173770334266246861770", "0", "4720763745722683616702324599137259461509439547324750011830105416383780791263", "4844030361230692908091131578688419341633213823133966379083981236400104720538", "16547485850637761685", "0", "0", "0"],
      "userAuthClaimMtp": ["20414019172782894011037632981443152254877376319211511372476935057674492820400", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userAuthClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userAuthClaimNonRevMtpAuxHi": "0",
      "userAuthClaimNonRevMtpAuxHv": "0",
      "userAuthClaimNonRevMtpNoAux": "1",
      "userClaimsTreeRoot": "4007604929687835641683076505379836604617083797856462347907321779859723516350",
      "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272",
      "userRevTreeRoot": "0",
      "userRootsTreeRoot": "0",
      "userState": "17722469129507053741573719341978204391758087537322007148901451934391296362335",
      "userStateInOnChainSmtMtp": ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "19991091798052235227442886829713443191817461077589875647331508266325270343516", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
      "userStateInOnChainSmtMtpAuxHi": "0",
      "userStateInOnChainSmtMtpAuxHv": "0",
      "userStateInOnChainSmtMtpNoAux": "0",
      "userStateInOnChainSmtRoot": "9868400991696380187039155240914507327007550684366042959000080351486388831719",
      "verifierCorrelationID": "123456789",
    }

    const witness = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(witness);
  });

});
