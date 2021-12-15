const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("idState test", function () {
    this.timeout(200000);

    // TODO fix this test
    it("Test IdState", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idState.circom"),
            {reduceConstraints: false}
        );

        // input data generated with circuits/test/testvectorsgen/idState_test.go, which uses go-iden3-core
        const witness = await circuit.calculateWitness({
            id: "409978454789059524516255530518320524248375026226842546929624045275356135424",
            oldIdState: "15406467229439115550895214376290248281834905021622756580001140373731264617834",
            userPrivateKey: "4883183928383535563675582976463370989628503468966767560017433840589864308760",
            siblings: ["0", "0", "0", "0"],
            claimsTreeRoot: "18553533303728791593447168679992702561830101690674887677317689732610999720086",
            newIdState: "13546139455567701992520470295344329962254176120482961837827842024291363749536"
        });
        await circuit.checkConstraints(witness);
        await circuit.assertOut(witness, {id: "409978454789059524516255530518320524248375026226842546929624045275356135424", oldIdState: "15406467229439115550895214376290248281834905021622756580001140373731264617834", newIdState: "13546139455567701992520470295344329962254176120482961837827842024291363749536"});
    });
});
