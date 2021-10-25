const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("buildClaimBasicAboutId test (old)", function () {
    this.timeout(200000);

    it("Test BuildClaimBasicAboutId", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "buildClaimBasicAboutId.circom"),
            {reduceConstraints: false}
        );
        const witness = await circuit.calculateWitness({
            id: "90379192157127074746780252349470665474172144646890885515776838193381376"
        }, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {hi: "8108938826288806943654937928392056767304451246257809977892029122345121642608"});
        await circuit.assertOut(witness, {hv: "951383894958571821976060584138905353883650994872035011055912076785884444545"});
     });
});
