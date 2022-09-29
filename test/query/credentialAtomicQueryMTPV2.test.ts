import { describe } from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("Test credential atomic query MTP V2", function () {
  this.timeout(600000);

  let circuit;

  before(async () => {
    circuit = await wasm_tester(
      path.join(
        __dirname,
        "../circuits/query",
        "credentialAtomicQueryMTPTestV2.circom"
      ),
      {
        output: path.join(__dirname, "circuits", "build"),
        recompile: true,
        reduceConstraints: false,
      }
    );
  });

  after(async () => {
    circuit.release();
  });

  it("test credentialAtomicQueryMTP V2", async () => {
    // inputs MUST be generated by GO-CIRCUITS library https://github.com/iden3/go-circuits (using corresponding test)
    const inputs = {
      userAuthClaim: [
        "304427537360709784173770334266246861770",
        "0",
        "17640206035128972995519606214765283372613874593503528180869261482403155458945",
        "20634138280259599560273310290025659992320584624461316485434108770067472477956",
        "15930428023331155902",
        "0",
        "0",
        "0",
      ],
      userAuthClaimMtp: [
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
      ],
      userAuthClaimNonRevMtp: [
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
      ],
      userAuthClaimNonRevMtpAuxHi: "10",
      userAuthClaimNonRevMtpAuxHv: "0",
      userAuthClaimNonRevMtpNoAux: "0",
      userClaimsTreeRoot:
        "9763429684850732628215303952870004997159843236039795272605841029866455670219",
      userState:
        "11660131514240312423013645096623187768802468304351121097689799587038871517788",
      userRevTreeRoot:
        "8622644894675942381874564342994639469688648860091849950271736143992882987125",
      userRootsTreeRoot: "0",
      userID:
        "379949150130214723420589610911161895495647789006649785264738141299135414272",
      challenge: "583091486781463398742321306787801699791102451699",
      challengeSignatureR8x:
        "4342068361442898452581009657103936652978711595095953654678237562243284711540",
      challengeSignatureR8y:
        "1664501846673733427007295110341185564342546241958817201534478584174411116567",
      challengeSignatureS:
        "1340856461644564719800127695529262156959703969851851894934558336242926191690",
      issuerClaim: [
        "3613283249068442770038516118105710406958",
        "379949150130214723420589610911161895495647789006649785264738141299135414272",
        "19960523",
        "1",
        "30803922965249841627828060161",
        "0",
        "0",
        "0",
      ],
      issuerClaimClaimsTreeRoot:
        "20618217020136820019856815142102224866610775639472765272961915168910735675621",
      issuerClaimIdenState:
        "2835556363112754126224036259944992967187212926956738279913811552470617526188",
      issuerClaimMtp: [
        "0",
        "0",
        "0",
        "18337129644116656308842422695567930755039142442806278977230099338026575870840",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
      ],
      issuerClaimRevTreeRoot: "0",
      issuerClaimRootsTreeRoot: "0",
      issuerClaimNonRevClaimsTreeRoot:
        "20618217020136820019856815142102224866610775639472765272961915168910735675621",
      issuerClaimNonRevRevTreeRoot: "0",
      issuerClaimNonRevRootsTreeRoot: "0",
      issuerClaimNonRevState:
        "2835556363112754126224036259944992967187212926956738279913811552470617526188",
      issuerClaimNonRevMtp: [
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
      ],
      issuerClaimNonRevMtpAuxHi: "0",
      issuerClaimNonRevMtpAuxHv: "0",
      issuerClaimNonRevMtpNoAux: "1",
      claimSchema: "210459579859058135404770043788028292398",
      issuerID:
        "26599707002460144379092755370384635496563807452878989192352627271768342528",
      operator: 2,
      slotIndex: 2,
      timestamp: "1642074362",
      value: [
        "20020101",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
      ],
    };
    const expOut = {
      valueHash:
        "17614135090035519137778424604458860432455192195724904809712098442213690177861",
      challenge: "583091486781463398742321306787801699791102451699",
      userID:
        "379949150130214723420589610911161895495647789006649785264738141299135414272",
      claimSchema: "210459579859058135404770043788028292398",
      userState:
        "11660131514240312423013645096623187768802468304351121097689799587038871517788",
      issuerClaimIdenState:
        "2835556363112754126224036259944992967187212926956738279913811552470617526188",
      issuerClaimNonRevState:
        "2835556363112754126224036259944992967187212926956738279913811552470617526188",
      slotIndex: "2",
      operator: "2",
      timestamp: "1642074362",
      issuerID:
        "26599707002460144379092755370384635496563807452878989192352627271768342528",
    };
    const w = await circuit.calculateWitness(inputs, true);

    await circuit.checkConstraints(w);
    await circuit.assertOut(w, expOut);
  });
});
