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
            issuerRoot: "4615338232455508897948660824298151828328838846582024144913163447606519826728",
            mtp: ["0", "0", "0", "0"],
            id: "90379192157127074746780252349470665474172144646890885515776838193381376",
            oUserPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            oPbkAx: "17640206035128972995519606214765283372613874593503528180869261482403155458945",
            oPbkAy: "20634138280259599560273310290025659992320584624461316485434108770067472477956",
            oMtp: ["0", "0", "0", "0"],
            oClaimsTreeRoot: "7752817182466821024912691617317281994168382184623539399016584393749253197138",
            oRevTreeRoot: "0",
            oRootsTreeRoot: "16040558507799920458961815866533497687655590061696007002153111557294098590818"
        });
        assert(circuit.checkWitness(witness));
     });
});
