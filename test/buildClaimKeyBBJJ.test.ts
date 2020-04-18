const path = require("path");
const tester = require("circom").tester;
const circomlib = require("circomlib");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("buildClaimKeyBBJJ test", function () {
    this.timeout(200000);
    it("Test BuildClaimKeyBBJJ", async () => {
        const circuit = await tester(
                    path.join(__dirname, "circuits", "buildClaimKeyBBJJ.circom")
        );

        const ay = "20634138280259599560273310290025659992320584624461316485434108770067472477956";

        const witness = await circuit.calculateWitness({
            ax: "17640206035128972995519606214765283372613874593503528180869261482403155458945",
            ay: "20634138280259599560273310290025659992320584624461316485434108770067472477956"
        }, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {hi: "13983541343321049801827232936939574644850750015280974697557168766727391751003"});
        await circuit.assertOut(witness, {hv: "951383894958571821976060584138905353883650994872035011055912076785884444545"});
     });
});
