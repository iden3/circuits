const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const circomlib = require("circomlib");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("buildClaimAuthKSignBBJJ test", function () {
    this.timeout(200000);

    const levels : number = 3;

    it("Test BuildClaimAuthKSignBBJJ", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "buildClaimAuthKSignBBJJ.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        const ay = "20634138280259599560273310290025659992320584624461316485434108770067472477956";
        // const ay = "2006343756953729302788634646776432144113870616756499754430019488750560779821"; // SwapEndianness

        const witness = circuit.calculateWitness({
            ax: "17640206035128972995519606214765283372613874593503528180869261482403155458945",
            ay: "20634138280259599560273310290025659992320584624461316485434108770067472477956"
        });
        assert(circuit.checkWitness(witness));
    
        const rHi = witness[circuit.getSignalIdx("main.hi")];
        const rHv = witness[circuit.getSignalIdx("main.hv")];

        assert.equal(rHi.toString(), "18026127644511512188499055513029449402455853238246965393418850143730028895665", "not equal");
        assert.equal(rHv.toString(), "951383894958571821976060584138905353883650994872035011055912076785884444545", "not equal");
     });
});
