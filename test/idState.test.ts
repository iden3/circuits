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
            id: "90379192157127074746780252349470665474172144646890885515776838193381376",
            nullifier: "6719425020119894285603660287755604118800506919944842740223442123517138826271",
            oldIdState: "0",
            userPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            pbkAx: "17640206035128972995519606214765283372613874593503528180869261482403155458945",
            pbkAy: "20634138280259599560273310290025659992320584624461316485434108770067472477956",
            mtp: ["0", "0", "0", "0"],
            claimsTreeRoot: "7752817182466821024912691617317281994168382184623539399016584393749253197138",
            revTreeRoot: "0",
            rootsTreeRoot: "16040558507799920458961815866533497687655590061696007002153111557294098590818",
            newIdState: "90379192157127074746780252349470665474172144646890885515776838193381376"
        });
        assert(circuit.checkWitness(witness));
        // const out0 = witness[circuit.getSignalIdx("main.out0")];
        // const out1 = witness[circuit.getSignalIdx("main.out1")];
        // console.log(out0);
        // console.log(out1);
    });
});
