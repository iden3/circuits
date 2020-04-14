const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("credential test", function () {
    this.timeout(200000);


    it("Test Credential simple tree", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "credential.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);
    
        // input data generated with circuits/test/testvectorsgen/credential_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            issuerRoot: "20345323600276915334840455511884465229803859322011240311319051873466365756230",
            mtp: ["0", "0", "0", "0"],
            id: "418819843184716391854950027336187830212226236089582432322628806588929540096",
            oUserPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            oMtp: ["0", "0", "0", "0"],
            oClaimsTreeRoot: "19759495200350784025545259483378281480848861021788190330947710448581962628389",
            oRevTreeRoot: "0",
            oRootsTreeRoot: "4993494596562389383889749727008725160160552507022773815483402975297010560970"
        });
        assert(circuit.checkWitness(witness));
     });

});
