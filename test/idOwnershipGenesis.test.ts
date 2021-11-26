const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idOwnershipGenesis test", function () {
    this.timeout(200000);

    // TODO fix this test
    xit("Test IdOwnershipGenesis", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idOwnershipGenesis.circom"),
            {reduceConstraints: false}
        );

        const privKStr = "6190793965647866647574058687473278714480561351424348391693421151024369116465";

        // input data generated with circuits/test/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = await circuit.calculateWitness({
            id: "436488163496163801239772944702740493390396197235644466912178158704332374016",
            userPrivateKey: "4957679760459508851420863521780560830598415356609971490286236508349735930306",
            siblings: ["0", "0", "0", "0"],
            claimsTreeRoot: "1729006260119089712818713806538777619892421181772209370118162803020343827555",
        });
        await circuit.checkConstraints(witness);
    });
});
