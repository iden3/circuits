import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

describe("authWithRelay.circom:", async function() {
    const tests = [
        {
            desc: "success",
            input: {
                claimsTreeRoot: "8033159210005724351649063848617878571712113104821846241291681963936214187701",
                authClaimMtp: ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
                authClaim: ["269270088098491255471307608775043319525", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
                revTreeRoot: "0",
                authClaimNonRevMtp: ["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
                authClaimNonRevMtpNoAux: "1",
                authClaimNonRevMtpAuxHi: "0",
                authClaimNonRevMtpAuxHv: "0",

                rootsTreeRoot: "0",

                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",

                state: "5816868615164565912277677884704888703982258184820398645933682814085602171910",
                userID: "286312392162647260160287083374160163061246635086990474403590223113720496128",

                relayState: "5465777564118594901595902393084861846772239832530659318550337132016303395881",
                userStateInRelayClaimMtp:  ["0","2609910676143495607892461791305526341937185018642920404820336264363312964848","0","0"],
                userStateInRelayClaim: ["981208330819247466821056791934709559638","286312392162647260160287083374160163061246635086990474403590223113720496128","0","0","0","0","5816868615164565912277677884704888703982258184820398645933682814085602171910","0"],
                relayProofValidClaimsTreeRoot: "13781894680034216280892647143823624902862234208494740350287172799879633358850",
                relayProofValidRevTreeRoot: "0",
                relayProofValidRootsTreeRoot: "0",
            },
        },
    ];

    let circuit;
    this.timeout(300000)

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits", "authWithRelay.circom"),
            {
                reduceConstraints: false,
                output: path.join(__dirname, "../circuits", "build/authWithRelay"),
                recompile: true,
            }
        );
    });

    tests.forEach(({desc, input}) => {
        it(`auth ${desc}`, async () => {
            const w = await circuit.calculateWitness(input, true);
            await circuit.checkConstraints(w);
        });
    });
});
