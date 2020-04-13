
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const circomlib = require("circomlib");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("poseidon test", function () {
    this.timeout(200000);

    const levels : number = 3;

    it("Test poseidon compatibility with go-iden3-crypto/poseidon", async () => {
        const compiledCircuit = await compiler(
                    path.join(__dirname, "circuits", "poseidon.circom"),
                    { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        let witness = circuit.calculateWitness({
            in: ["0", "0", "0"]
        });
        assert(circuit.checkWitness(witness));
        let out = witness[circuit.getSignalIdx("main.out")];
        assert.equal(out.toString(), "951383894958571821976060584138905353883650994872035011055912076785884444545", "not equal");

        witness = circuit.calculateWitness({
            in: ["1", "0", "0"]
        });
        assert(circuit.checkWitness(witness));
        out = witness[circuit.getSignalIdx("main.out")];
        assert.equal(out.toString(), "2279272124503809695177170942549831206840003426178943720957919922723804431629", "not equal");

        // check circomlib javascript poseidon output
        const jsPoseidon = circomlib.poseidon.createHash(6, 8, 57);
        let jsOut = jsPoseidon([1, 0, 0]).toString();
        assert.equal(jsOut, "2279272124503809695177170942549831206840003426178943720957919922723804431629", "not equal");

        witness = circuit.calculateWitness({
            in: ["2", "0", "0"]
        });
        assert(circuit.checkWitness(witness));
        out = witness[circuit.getSignalIdx("main.out")];
        assert.equal(out.toString(), "13132721937331725951616278520078927153934890115891049388516726302689567578587", "not equal");

        // SWAPPED DATA test
        // witness = circuit.calculateWitness({
        //     in: ["6277101735386680763835789423207666416102355444464034512896", "452312848583266388373324160190187140051835877600158453279131187530910662656", "2006343756953729302788634646776432144113870616756499754430019488750560779821"]
        // });
        // assert(circuit.checkWitness(witness));
        // out = witness[circuit.getSignalIdx("main.out")];
        // assert.equal(out.toString(), "17611975394326802955172662837194865111253549123001923344930051470191931257028", "not equal");

        const testValues = ["72057594037927936", "1", "20634138280259599560273310290025659992320584624461316485434108770067472477956"];
        witness = circuit.calculateWitness({
            in: testValues
        });
        assert(circuit.checkWitness(witness));
        out = witness[circuit.getSignalIdx("main.out")];
        assert.equal(out.toString(), "10395143007367284783361235630029585391855532481545192724789751124286001219030", "not equal");

        // check circomlib javascript poseidon output
        jsOut = jsPoseidon(testValues).toString();
        assert.equal(jsOut, "10395143007367284783361235630029585391855532481545192724789751124286001219030", "not equal");
        
     });
});

