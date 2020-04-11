const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("credential test", function () {
    this.timeout(200000);


    it("Test Credential", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "credential.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        // input data generated with circuits/testvectorsgen/credential_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            issuerRoot: "13724315490236840804604964254304298078578342879632183385476146055229784236845",
            mtp: ["0", "0", "0", "0"],
            id: "42480995223634099390927232964573436282320794921974209609166261920409845760",
            oUserPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            oPbkSign: "1",
            oPbkAy: "20634138280259599560273310290025659992320584624461316485434108770067472477956",
            oMtp: ["0", "0", "0", "0"],
            oClaimsTreeRoot: "6963859623793454942121025237799996624720342105089146156138614533550950268330",
            oRevTreeRoot: "0",
            oRootsTreeRoot: "11557043531030918784902190516497945231385453453624054983601946230075316333252"
        });
        assert(circuit.checkWitness(witness));
     });
});
