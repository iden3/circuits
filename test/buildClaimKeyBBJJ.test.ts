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
            ax: "17640206035128972995519606214765283372613874593503528180869261482403155458945",
            ay: "20634138280259599560273310290025659992320584624461316485434108770067472477956"
        }, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {hi: "21194384538535854141301572543647862109415814559971895464714089489459043607338"});
        await circuit.assertOut(witness, {hv: "2351654555892372227640888372176282444150254868378439619268573230312091195718"});
     });
});
