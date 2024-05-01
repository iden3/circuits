import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;


describe("ValueCommitment test", function () {
    let valueCommitmentCircuit;

    before(async function () {
        valueCommitmentCircuit = await wasm_tester(path.join(__dirname, "../circuits/query/", "valueCommitmentTest.circom"));
    });

    it("should commit a value with a non-zero nonce", async () => {
        const inputs = { value: "5", commitNonce: "7" };
        const expectedOut = { out: "21007229687521157814825902919006068496120320911167801732994749038798743998593" };

        const witness = await valueCommitmentCircuit.calculateWitness(inputs, true);
        await valueCommitmentCircuit.assertOut(witness, expectedOut);
        await valueCommitmentCircuit.checkConstraints(witness);
    });

    it("should return zero for a commit with zero nonce", async () => {
        const inputs = { value: "10", commitNonce: "0" };
        const expectedOut = { out: "0" };

        const witness = await valueCommitmentCircuit.calculateWitness(inputs, true);
        await valueCommitmentCircuit.assertOut(witness, expectedOut);
        await valueCommitmentCircuit.checkConstraints(witness);
    });
});