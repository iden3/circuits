const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("idState", function() {
    this.timeout(600000);

    it("1 auth claim is in the claims tree. Add 1 more auth claim to the claims tree.", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "idState.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: false,
                reduceConstraints: false,
            },
        );

        const inputs = {
            oldIdState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
            newIdState: "6243262098189365110173326120466238114783380459336290130750689570190357902007",

            claimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
            authClaimMtp: ["0", "0", "0", "0"],
            authClaim : [
                "251025091000101825075425831481271126140",
                "0",
                "17640206035128972995519606214765283372613874593503528180869261482403155458945",
                "20634138280259599560273310290025659992320584624461316485434108770067472477956",
                "15930428023331155902",
                "0",
                "0",
                "0",
            ],

            revTreeRoot: "0",
            authClaimNonRevMtp: ["0", "0", "0", "0"],
            authClaimNonRevMtpNoAux: "1",
            authClaimNonRevMtpAuxHv: "0",
            authClaimNonRevMtpAuxHi: "0",

            rootsTreeRoot: "0",

            signatureR8x: "11075012579941724482110814276848025919659518812841198498785625658594849865723",
            signatureR8y: "5397153531138549045310069778129455516182753644379535707118963304821960685553",
            signatureS: "994528294951187360742259972174181258886964968450592514979671695886540429602",
        };
        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
});
