const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const circomlib = require("circomlib");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("buildClaimBasicAboutId test", function () {
    this.timeout(200000);

    const levels : number = 3;

    it("Test BuildClaimBasicAboutId", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "buildClaimBasicAboutId.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        const witness = circuit.calculateWitness({
            id: "1526306386667696699751338020294850047314334048323423451965519591836440"
        });
        assert(circuit.checkWitness(witness));
    
        const rHi = witness[circuit.getSignalIdx("main.hi")];
        const rHv = witness[circuit.getSignalIdx("main.hv")];

        assert.equal(rHi.toString(), "12734049711055761433488870890598520976407418887645073210334330682303276431766", "not equal");
        assert.equal(rHv.toString(), "951383894958571821976060584138905353883650994872035011055912076785884444545", "not equal");
     });
});
