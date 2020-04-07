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
            id: "42480995223634099390927232964573436282320794921974209609166261920409845760",
            userPrivateKey: privKStr,
            pbkSign: "1",
            pbkAy: "20634138280259599560273310290025659992320584624461316485434108770067472477956",
            mtp: ["0", "0", "0", "0"], // extra 0 at the end, circom leaf protection
            claimsTreeRoot: "6963859623793454942121025237799996624720342105089146156138614533550950268330",
            revTreeRoot: "0",
            rootsTreeRoot: "11557043531030918784902190516497945231385453453624054983601946230075316333252",
        });
        assert(circuit.checkWitness(witness));
     });
});
