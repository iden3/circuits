import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

export {};

describe("credentialAtomicQueryMTPWithRelayTest", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/query", "credentialAtomicQueryMTPWithRelayTest.circom"),
            {
                output: path.join(__dirname, "../circuits", "build", "credentialAtomicQueryMTPWithRelayTest"),
                recompile: true,
                reduceConstraints: false,
            },
        );
    });

    after(async () => {
        circuit.release()
    })

    it("credentialAtomicQueryMTPWithRelayTest", async () => {

        const inputs = {"userAuthClaim":["269270088098491255471307608775043319525","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"1","challengeSignatureR8x":"8553678144208642175027223770335048072652078621216414881653012537434846327449","challengeSignatureR8y":"5507837342589329113352496188906367161790372084365285966741761856353367255709","challengeSignatureS":"2093461910575977345603199789919760192811763972089699387324401771367839603655","issuerClaim":["3677203805624134172815825715044445108615","286312392162647260160287083374160163061246635086990474403590223113720496128","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","issuerClaimIdenState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","issuerClaimMtp":["0","3007906543589053223183609977424583669571967498470079791401931468580200755448","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimRevTreeRoot":"0","issuerClaimRootsTreeRoot":"0","issuerClaimNonRevClaimsTreeRoot":"12781049434766209895790529815771921100011665835724745028505992240548230711728","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"20606705619830543359176597576564222044873771515109680973150322899613614552596","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"274380136414749538182079640726762994055","issuerID":"296941560404583387587196218166209608454370683337298127000644446413747191808","operator":0,"relayProofValidClaimsTreeRoot":"2854665891046135459434995383199781762190358117579623998115936884038963331048","relayProofValidRevTreeRoot":"0","relayProofValidRootsTreeRoot":"0","relayState":"16294564286985950894527527840426853346844847075954975086655280191624111272054","slotIndex":2,"timestamp":"1642074362","userClaimsTreeRoot":"8033159210005724351649063848617878571712113104821846241291681963936214187701","userID":"286312392162647260160287083374160163061246635086990474403590223113720496128","userRevTreeRoot":"0","userRootsTreeRoot":"0","userStateInRelayClaim":["981208330819247466821056791934709559638","286312392162647260160287083374160163061246635086990474403590223113720496128","0","0","0","0","5816868615164565912277677884704888703982258184820398645933682814085602171910","0"],"userStateInRelayClaimMtp":["0","1501244652861114532352800692615798696848833011443509616387313576023182892460","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}

        const expOut = {
            challenge: "1",
            userID: "286312392162647260160287083374160163061246635086990474403590223113720496128",
            claimSchema: "274380136414749538182079640726762994055",
            slotIndex: "2",
            operator: "0",
            timestamp: "1642074362",
            issuerID: "296941560404583387587196218166209608454370683337298127000644446413747191808",
        }

        const w = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(w);
        await circuit.assertOut(w, expOut);
    });

});
