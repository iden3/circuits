
const path = require("path");
const snarkjs = require("snarkjs");
const tester = require("circom").tester;
const circomlib = require("circomlib");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("poseidon test", function () {
    this.timeout(200000);

    const levels : number = 3;

    it("Test poseidon compatibility with go-iden3-crypto/poseidon", async () => {
        const circuit = await tester(
                    path.join(__dirname, "circuits", "poseidon.circom"),
                    { reduceConstraints: false }
        );

        let witness = await circuit.calculateWitness({
            in: ["0", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "951383894958571821976060584138905353883650994872035011055912076785884444545"});

        witness = await circuit.calculateWitness({
            in: ["1", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "2279272124503809695177170942549831206840003426178943720957919922723804431629"});

        // check circomlib javascript poseidon output
        const jsPoseidon = circomlib.poseidon.createHash(6, 8, 57);
        let jsOut = jsPoseidon([1, 0, 0]).toString();
        assert.equal(jsOut, "2279272124503809695177170942549831206840003426178943720957919922723804431629", "not equal");

        witness = await circuit.calculateWitness({
            in: ["2", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "13132721937331725951616278520078927153934890115891049388516726302689567578587"});

        const testValues = ["72057594037927936", "1", "20634138280259599560273310290025659992320584624461316485434108770067472477956"];
        witness = await circuit.calculateWitness({
            in: testValues
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "10395143007367284783361235630029585391855532481545192724789751124286001219030"});

        // check circomlib javascript poseidon output
        jsOut = jsPoseidon(testValues).toString();
        assert.equal(jsOut, "10395143007367284783361235630029585391855532481545192724789751124286001219030", "not equal");
        
     });
});

