const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("idState", function () {
    this.timeout(600000);

    // it("1 auth claim is in the claims tree. Add 1 more auth claim to the claims tree.", async () => {
    //     const circuit = await tester(
    //         path.join(__dirname, "circuits", "idStateTest.circom"),
    //         {
    //             output: path.join(__dirname, "circuits", "build"),
    //             recompile: true,
    //             reduceConstraints: false,
    //         },
    //     );
    //
    //     const inputs = {
    //         id: "323416925264666217617288569742564703632850816035761084002720090377353297920",
    //         oldIdState: "18311560525383319719311394957064820091354976310599818797157189568621466950811",
    //         newIdState: "6243262098189365110173326120466238114783380459336290130750689570190357902007",
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
    //         path.join(__dirname, "circuits", "idStateTest.circom"),
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
    //         "id": "356993913155855432799649482520123310103696210589421536464905889646930493440",
    //         "newIdState": "17268442397954957023777367454402134865562796216851187969412301340920628455659",
    //         "oldIdState": "4184931649847803667202237732911450570986787389402491101188838319583389264794",
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
            path.join(__dirname, "circuits", "idStateTest.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

        const inputs = {
            "authClaim": ["269270088098491255471307608775043319525", "0", "13472757775376226321593595905385246220746328515604713873616318056285586242303", "16586685563688622056787077821051457975731591143161121084121927593789265754171", "0", "0", "0", "0"],
            "authClaimMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtpAuxHi": "0",
            "authClaimNonRevMtpAuxHv": "0",
            "authClaimNonRevMtpNoAux": "1",
            "claimsTreeRoot": "7080158925658360173572117351438458775187308620048444661932566860021946691911",
            "id": "254516485417117669604883746489712311182469560895998296557398532694025109504",
            "newIdState": "5465748102760201017766487342967635788590869694748561099468758455034533291556",
            "oldIdState": "13176599323901742742055581761244662470012062489876892454255630909560071027835",
            "revTreeRoot": "0",
            "rootsTreeRoot": "0",
            "signatureR8x": "18373221186084427683374638449053384615755216533374169264284121192617707419166",
            "signatureR8y": "15216534799230179074507824494565066265405874459062867133515158967960648963367",
            "signatureS": "1401701613641450827417367863112801024537848115746640104541196624775116764071"
        }

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });

});

