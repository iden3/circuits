const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("date test", function () {
    this.timeout(200000);

    it("Test date", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "date.circom"),
            {reduceConstraints: false}
        );

        // input data generated with circuits/test/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = await circuit.calculateWitness(
            { yyyymmdd : 19960424 },
        );
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {year: "1996", month: "4", day: "24"});
    });
});
