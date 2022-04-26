const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("StateTransition", function () {
    this.timeout(600000);

    // it("1 auth claim is in the claims tree. Add 1 more auth claim to the claims tree.", async () => {
    //     const circuit = await tester(
    //         path.join(__dirname, "circuits", "stateTransitionTest.circom"),
    //         {
    //             output: path.join(__dirname, "circuits", "build"),
    //             recompile: true,
    //             reduceConstraints: false,
    //         },
    //     );
    //
    //     const inputs = {
    //         userID: "323416925264666217617288569742564703632850816035761084002720090377353297920",
    //         oldUserState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
    //         newUserState: "6243262098189365110173326120466238114783380459336290130750689570190357902007",
    //
    //         claimsTreeRoot: "14501975351413460283779241106398661838785725538630637996477950952692691051377",
    //         authClaimMtp: ["0", "0", "0", "0"],
    //         authClaim: [
    //             "251025091000101825075425831481271126140",
    //             "0",
    //             "17640206035128972995519606214765283372613874593503528180869261482403155458945",
    //             "20634138280259599560273310290025659992320584624461316485434108770067472477956",
    //             "15930428023331155902",
    //             "0",
    //             "0",
    //             "0",
    //         ],
    //
    //         revTreeRoot: "0",
    //         authClaimNonRevMtp: ["0", "0", "0", "0"],
    //         authClaimNonRevMtpNoAux: "1",
    //         authClaimNonRevMtpAuxHv: "0",
    //         authClaimNonRevMtpAuxHi: "0",
    //
    //         rootsTreeRoot: "0",
    //
    //         signatureR8x: "11075012579941724482110814276848025919659518812841198498785625658594849865723",
    //         signatureR8y: "5397153531138549045310069778129455516182753644379535707118963304821960685553",
    //         signatureS: "994528294951187360742259972174181258886964968450592514979671695886540429602",
    //     };
    //     const witness = await circuit.calculateWitness(inputs);
    //     await circuit.checkConstraints(witness);
    // });
    // it("2 claims is in the claims tree. 1 claim is revoked in the new state", async () => {
    //     const circuit = await tester(
    //         path.join(__dirname, "circuits", "stateTransitionTest.circom"),
    //         {
    //             output: path.join(__dirname, "circuits", "build"),
    //             recompile: true,
    //             reduceConstraints: false,
    //         },
    //     );
    //
    //     const inputs = {
    //         "authClaim": ["164867201768971999401702181843803888060", "0", "7300649550205612486228899891217695903089779102579429373585367581317710884000", "6970483435706206779191000293650113939729483945639018728473720645003606620482", "0", "0", "0", "0"],
    //         "authClaimMtp": ["0", "16092190476846329069843047448582699438496079865887284180081491262071461344762", "0", "0"],
    //         "authClaimNonRevMtp": ["0", "0", "0", "0"],
    //         "authClaimNonRevMtpAuxHi": "0",
    //         "authClaimNonRevMtpAuxHv": "0",
    //         "authClaimNonRevMtpNoAux": "1",
    //         "claimsTreeRoot": "4391004575225191356091924845925138609981629126838337482351782494426166055282",
    //         "userID": "356993913155855432799649482520123310103696210589421536464905889646930493440",
    //         "newUserState": "17268442397954957023777367454402134865562796216851187969412301340920628455659",
    //         "oldUserState": "4184931649847803667202237732911450570986787389402491101188838319583389264794",
    //         "revTreeRoot": "0",
    //         "rootsTreeRoot": "0",
    //         "signatureR8x": "21420402936832933857351985953119059381042904267374802779170746082355708622343",
    //         "signatureR8y": "15239079946308547193393570674850271510780375099678267504348575412450333359418",
    //         "signatureS": "1981626348094407680688824986506539882285461311267930146632869703489539082496"
    //     }
    //     const witness = await circuit.calculateWitness(inputs);
    //     await circuit.checkConstraints(witness);
    // });
    //

    it("1 auth claim is in the claims tree.", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "stateTransitionTest.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

        const inputs = {
            authClaim: ["304427537360709784173770334266246861770", "0", "9582165609074695838007712438814613121302719752874385708394134542816240804696", "18271435592817415588213874506882839610978320325722319742324814767882756910515", "11203087622270641253", "0", "0", "0"],
            authClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            authClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            authClaimNonRevMtpAuxHi: "0",
            authClaimNonRevMtpAuxHv: "0",
            authClaimNonRevMtpNoAux: "1",
            userID: "26599707002460144379092755370384635496563807452878989192352627271768342528",
            newUserState: "7569111473237253646417788189126468973900432716598921661470118514516731079797",
            oldUserState: "6317996369756476782464660619835940615734517981889733696047139451453239145426",
            claimsTreeRoot: "18337129644116656308842422695567930755039142442806278977230099338026575870840",
            revTreeRoot: "0",
            rootsTreeRoot: "0",
            signatureR8x: "9484102035827996121666608170002743002783492772260590322761477321381254509037",
            signatureR8y: "19295134567339498210855406074518612682643335122341225376941332925036431891102",
            signatureS: "282291664505682519059669624505331509305429004374837545959385601323093440910"
        }

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });

});
