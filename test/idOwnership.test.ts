const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idOwnership test (asserted values need to be fixed)", function () {
    this.timeout(200000);

    // TODO fix this test
    xit("Test IdOwnership", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idOwnership.circom"),
            {reduceConstraints: false}
        );

        const privKStr = "6190793965647866647574058687473278714480561351424348391693421151024369116465";

        // input data generated with circuits/test/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = await circuit.calculateWitness({
            id: "418819843184716391854950027336187830212226236089582432322628806588929540096",
            userPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            siblings: ["0", "0", "0", "0"],
            claimsTreeRoot: "19759495200350784025545259483378281480848861021788190330947710448581962628389",
            revTreeRoot: "0",
            rootsTreeRoot: "4993494596562389383889749727008725160160552507022773815483402975297010560970"
        });
        await circuit.checkConstraints(witness);
    });
});
