const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("buildClaimKeyBBJJ test", function () {
    this.timeout(200000);
    it("Test BuildClaimKeyBBJJ", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "buildClaimKeyBBJJ.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness({
            ax: "14195501157940592395079211812758919046533606432336046888592118920316492420198",
            ay: "17942339684132884401246422805771213865436132815007912305229040867670385221126"
        }, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {hi: "19720991581867396721458435993552086629070484476749609618354421752183185109266"});
        await circuit.assertOut(witness, {hv: "2351654555892372227640888372176282444150254868378439619268573230312091195718"});
     });
});
