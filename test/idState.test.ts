const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idState test", function () {
    this.timeout(200000);


    it("Test IdState", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "idState.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        const privKStr = "6190793965647866647574058687473278714480561351424348391693421151024369116465";

        // input data generated with circuits/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            nullifier: "1", // not used yet
            oldIdState: "1", // not used yet
            userPrivateKey: privKStr,
            pbkSign: "1",
            pbkAy: "20634138280259599560273310290025659992320584624461316485434108770067472477956",
            mtp: ["0", "0", "0", "0"], // extra 0 at the end, circom leaf protection
            claimsTreeRoot: "6963859623793454942121025237799996624720342105089146156138614533550950268330",
            revTreeRoot: "1", // not used yet
            rootsTreeRoot: "1", // not used yet
            newIdState: "1" // not used yet
        });
        assert(circuit.checkWitness(witness));
     });
});
