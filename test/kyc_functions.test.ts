const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;
const expect = chai.expect;

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

    it("Test kyc calculateAge 4", async () => {
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

        let err;
        try {
            await circuit.calculateWitness(inputs, true);
        } catch (e) {
            err = e;
        }
        expect(err).to.be.an('Error');
        expect(err.toString()).to.contain('Constraint doesn\'t match 0 != 1');
    });

    it("Test kyc calculateAge 5", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "kyc_calculateAge.circom"),
            {reduceConstraints: false},
        );
        const inputs = {
            "DOBYear": "2000",
            "DOBMonth": "10",
            "DOBDay": "9",
            "CurYear": "2000",
            "CurMonth": "10",
            "CurDay": "8",
        };

        let err;
        try {
            await circuit.calculateWitness(inputs, true);
        } catch (e) {
            err = e;
        }
        expect(err).to.be.an('Error');
        expect(err.toString()).to.contain('Constraint doesn\'t match 0 != 1');
    });
});
