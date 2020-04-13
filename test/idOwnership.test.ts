const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idOwnership test", function () {
    this.timeout(200000);


    it("Test IdOwnership", async () => {
        const compiledCircuit = await compiler(
            path.join(__dirname, "circuits", "idOwnership.circom"),
            { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        const privKStr = "6190793965647866647574058687473278714480561351424348391693421151024369116465";

        // input data generated with circuits/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            id: "90379192157127074746780252349470665474172144646890885515776838193381376",
            userPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            mtp: ["0", "0", "0", "0"],
            claimsTreeRoot: "7752817182466821024912691617317281994168382184623539399016584393749253197138",
            revTreeRoot: "0",
            rootsTreeRoot: "16040558507799920458961815866533497687655590061696007002153111557294098590818",
        });
        assert(circuit.checkWitness(witness));
    });
});
