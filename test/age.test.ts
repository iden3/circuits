const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("age test", function () {
    this.timeout(200000);

    it("Test age calculation", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "ageCalculation.circom"),
            {reduceConstraints: false}
        );

        const witness = await circuit.calculateWitness(
            {
                yyyymmdd : 19860524,
                currentDay: 16,
                currentMonth: 12,
                currentYear: 2021,
            },
        );
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {age: 35});
    });
});
