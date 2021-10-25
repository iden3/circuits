const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("kyc calculateAge test", function () {
    this.timeout(200000);
    it("Test kyc calculateAge 1", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "kyc_calculateAge.circom"),
            {reduceConstraints: false},
        );
        const inputs = {
            "DOBYear": "2000",
            "DOBMonth": "10",
            "DOBDay": "9",
            "CurYear": "2020",
            "CurMonth": "10",
            "CurDay": "9",
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {age: "20"});
    });

    it("Test kyc calculateAge 2", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "kyc_calculateAge.circom"),
            {reduceConstraints: false},
        );
        const inputs = {
            "DOBYear": "2000",
            "DOBMonth": "10",
            "DOBDay": "9",
            "CurYear": "2020",
            "CurMonth": "10",
            "CurDay": "8",
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {age: "19"});
    });

    it("Test kyc calculateAge 3", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "kyc_calculateAge.circom"),
            {reduceConstraints: false},
        );
        const inputs = {
            "DOBYear": "2000",
            "DOBMonth": "10",
            "DOBDay": "9",
            "CurYear": "2020",
            "CurMonth": "9",
            "CurDay": "30",
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {age: "19"});
    });

    it("Test kyc calculateAge 4 - expected to fail", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "kyc_calculateAge.circom"),
            {reduceConstraints: false},
        );
        const inputs = {
            "DOBYear": "2000",
            "DOBMonth": "10",
            "DOBDay": "9",
            "CurYear": "2000",
            "CurMonth": "9",
            "CurDay": "9",
        };

        const witness = await circuit.calculateWitness(inputs, true);
        // add method to expect constraint check fail
        await circuit.checkConstraints(witness);
        //await circuit.assertOut(witness, {age: "-1"});
    });
});
