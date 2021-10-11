
const path = require("path");
const snarkjs = require("snarkjs");
const tester = require("circom").tester;
const circomlib = require("circomlib");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("poseidon test", function () {
    this.timeout(200000);

    it("Test poseidon compatibility with circomlib/poseidon. 3 inputs", async () => {
        const circuit = await tester(
                    path.join(__dirname, "circuits", "poseidon.circom"),
                    { reduceConstraints: false }
        );

        let witness = await circuit.calculateWitness({
            in: ["0", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "5317387130258456662214331362918410991734007599705406860481038345552731150762"});

        witness = await circuit.calculateWitness({
            in: ["1", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "16319005924338521988144249782199320915969277491928916027259324394544057385749"});

        // check circomlib javascript poseidon output
        let jsOut = circomlib.poseidon([1, 0, 0]).toString();
        assert.equal(jsOut, "16319005924338521988144249782199320915969277491928916027259324394544057385749", "not equal");

        witness = await circuit.calculateWitness({
            in: ["2", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "13234400070188801104792523922697988244748411503422448631147834118387475842488"});

        const testValues = ["72057594037927936", "1", "20634138280259599560273310290025659992320584624461316485434108770067472477956"];
        witness = await circuit.calculateWitness({
            in: testValues
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "3135714887432857880402997813814046724922969450336546007917491784497158924950"});

        // check circomlib javascript poseidon output
        jsOut = circomlib.poseidon(testValues).toString();
        assert.equal(jsOut, "3135714887432857880402997813814046724922969450336546007917491784497158924950", "not equal");
    });

    it("Test poseidon compatibility with circomlib/poseidon. 14 inputs", async () => {

        // poseidon with 14 inputs
        const circuit = await tester(
            path.join(__dirname, "circuits", "poseidon14.circom"),
            { reduceConstraints: false }
        );

        let witness = await circuit.calculateWitness({
            in: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "8354478399926161176778659061636406690034081872658507739535256090879947077494"});

        // check circomlib javascript poseidon output
        let jsOut = circomlib.poseidon([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]).toString();
        assert.equal(jsOut, "8354478399926161176778659061636406690034081872658507739535256090879947077494", "not equal");

        witness = await circuit.calculateWitness({
            in: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "0", "0", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "5540388656744764564518487011617040650780060800286365721923524861648744699539"});

        // check circomlib javascript poseidon output
        jsOut = circomlib.poseidon([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0]).toString();
        assert.equal(jsOut, "5540388656744764564518487011617040650780060800286365721923524861648744699539", "not equal");
    });

    it("Test poseidon compatibility with circomlib/poseidon. 16 inputs", async () => {

        // poseidon with 16 inputs
        const circuit = await tester(
            path.join(__dirname, "circuits", "poseidon16.circom"),
            { reduceConstraints: false }
        );

        let witness = await circuit.calculateWitness({
            in: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "9989051620750914585850546081941653841776809718687451684622678807385399211877"});

        // check circomlib javascript poseidon output
        // let jsOut = circomlib.poseidon([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).toString();
        // assert.equal(jsOut, "9989051620750914585850546081941653841776809718687451684622678807385399211877", "not equal");

        witness = await circuit.calculateWitness({
            in: ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "0", "0", "0", "0", "0", "0"]
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {out: "11882816200654282475720830292386643970958445617880627439994635298904836126497"});

        // check circomlib javascript poseidon output
        // jsOut = circomlib.poseidon([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0]).toString();
        // assert.equal(jsOut, "11882816200654282475720830292386643970958445617880627439994635298904836126497", "not equal");
    });
});

