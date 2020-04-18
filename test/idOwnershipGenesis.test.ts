const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idOwnershipGenesis test", function () {
    this.timeout(200000);


    it("Test IdOwnershipGenesis", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idOwnershipGenesis.circom")
        );

        const privKStr = "6190793965647866647574058687473278714480561351424348391693421151024369116465";

        // input data generated with circuits/test/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = await circuit.calculateWitness({
            id: "418819843184716391854950027336187830212226236089582432322628806588929540096",
            userPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            siblings: ["0", "0", "0", "0"],
            claimsTreeRoot: "19759495200350784025545259483378281480848861021788190330947710448581962628389",
        });
        await circuit.checkConstraints(witness);
    });
});
