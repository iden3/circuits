const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idState test", function () {
    this.timeout(200000);


    it("Test IdState", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idState.circom"),
            {reduceConstraints: false}
        );

        // input data generated with circuits/test/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = await circuit.calculateWitness({
            id: "436488163496163801239772944702740493390396197235644466912178158704332374016",
            oldIdState: "0",
            userPrivateKey: "4957679760459508851420863521780560830598415356609971490286236508349735930306",
            siblings: ["0", "0", "0", "0"],
            claimsTreeRoot: "1729006260119089712818713806538777619892421181772209370118162803020343827555",
            newIdState: "436488163496163801239772944702740493390396197235644466912178158704332374016"
        });
        await circuit.checkConstraints(witness);
        // await circuit.assertOut(witness, {out0: "0"});
        // await circuit.assertOut(witness, {out1: "0"});
    });
});
