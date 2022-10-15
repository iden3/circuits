import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

// inputs MUST be generated by GO-CIRCUITS library https://github.com/iden3/go-circuits (using corresponding test)
describe("authV2Test.circom:", async function() {

    const tests = [
        {
            desc: "Ownership true. User state: genesis. Auth claims total/signedWith/revoked: 1/1/none",
            input: {
                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
                userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
                userAuthClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtpAuxHi: "0",
                userAuthClaimNonRevMtpAuxHv: "0",
                userAuthClaimNonRevMtpNoAux: "1",
                userClaimsTreeRoot: "9763429684850732628215303952870004997159843236039795272605841029866455670219",
                userGenesisID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
                userRevTreeRoot: "0",
                userRootsTreeRoot: "0",
                userSalt: "123456789",
                userState: "18656147546666944484453899241916469544090258810192803949522794490493271005313",
                globalSmtMtp: ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                globalSmtMtpAuxHi: "4",
                globalSmtMtpAuxHv: "300",
                globalSmtMtpNoAux: "0",
                globalSmtRoot: "2960269998131412406135915396987536312795307713692807443361231572350088373156",
            },
            output: {
                userID: "305769198989706509794076156820092188194874873901731374738387512556763611136",
            },
        },
        {
            desc: "Ownership true. User state: not-genesis. Auth claims total/signedWith/revoked: 1/1/none",
            input: {
                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
                userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
                userAuthClaimMtp: ["0", "0", "1243904711429961858774220647610724273798918457991486031567244100767259239747", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtpAuxHi: "0",
                userAuthClaimNonRevMtpAuxHv: "0",
                userAuthClaimNonRevMtpNoAux: "1",
                userClaimsTreeRoot: "3325296375493109531775738970103865437471502880293182874312109748701010548081",
                userGenesisID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
                userRevTreeRoot: "0",
                userRootsTreeRoot: "0",
                userSalt: "123456789",
                userState: "21556156816336611928260850205358242317673071374695788694657164635542250181506",
                globalSmtMtp: ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "19991091798052235227442886829713443191817461077589875647331508266325270343516", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                globalSmtMtpAuxHi: "0",
                globalSmtMtpAuxHv: "0",
                globalSmtMtpNoAux: "0",
                globalSmtRoot: "2527369248886058159298190241228260543545233125629989424050431010562778308348",
            },
            output: {
                userID: "305769198989706509794076156820092188194874873901731374738387512556763611136",
            },
        },
        {
            desc: "Ownership true. User state: not-genesis. Auth claims total/signedWith/revoked: 2/2/none",
            input: {
                challenge: "1",
                challengeSignatureR8x: "3318605682427930847043923964996627571509054270532204838981931388121839601904",
                challengeSignatureR8y: "6885828942356963641443098413925008636428756893590364657052219244852107012379",
                challengeSignatureS: "1239257276045842588253148642684748186882810960469506371777432113478495615573",
                userAuthClaim: ["304427537360709784173770334266246861770", "0", "4720763745722683616702324599137259461509439547324750011830105416383780791263", "4844030361230692908091131578688419341633213823133966379083981236400104720538", "16547485850637761685", "0", "0", "0"],
                userAuthClaimMtp: ["20414019172782894011037632981443152254877376319211511372476935057674492820400", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtpAuxHi: "0",
                userAuthClaimNonRevMtpAuxHv: "0",
                userAuthClaimNonRevMtpNoAux: "1",
                userClaimsTreeRoot: "4007604929687835641683076505379836604617083797856462347907321779859723516350",
                userGenesisID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
                userRevTreeRoot: "0",
                userRootsTreeRoot: "0",
                userSalt: "123456789",
                userState: "17722469129507053741573719341978204391758087537322007148901451934391296362335",
                globalSmtMtp: ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "19991091798052235227442886829713443191817461077589875647331508266325270343516", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                globalSmtMtpAuxHi: "0",
                globalSmtMtpAuxHv: "0",
                globalSmtMtpNoAux: "0",
                globalSmtRoot: "9868400991696380187039155240914507327007550684366042959000080351486388831719",
            },
            output: {
                userID: "305769198989706509794076156820092188194874873901731374738387512556763611136",
            },
        },
        {
            desc: "UserSalt=0. Nullifier == UserID should be true. Ownership true. User state: genesis. Auth claims total/signedWith/revoked: 1/1/none",
            input: {
                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
                userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
                userAuthClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtpAuxHi: "0",
                userAuthClaimNonRevMtpAuxHv: "0",
                userAuthClaimNonRevMtpNoAux: "1",
                userClaimsTreeRoot: "9763429684850732628215303952870004997159843236039795272605841029866455670219",
                userGenesisID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
                userRevTreeRoot: "0",
                userRootsTreeRoot: "0",
                userSalt: "0",
                userState: "18656147546666944484453899241916469544090258810192803949522794490493271005313",
                globalSmtMtp: ["0", "2740674427662457332835454792145677734479634481325332115749498841888350110548", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                globalSmtMtpAuxHi: "4",
                globalSmtMtpAuxHv: "300",
                globalSmtMtpNoAux: "0",
                globalSmtRoot: "2960269998131412406135915396987536312795307713692807443361231572350088373156",
            },
            output: {
                userID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
            },
        },
        {
            desc: "UserSalt=10. Nullifier == UserID should be true. Ownership true. User state: genesis. Auth claims total/signedWith/revoked: 1/1/none",
            input: {
                userGenesisID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
                userSalt: "10",
                userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
                userAuthClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                userAuthClaimNonRevMtpAuxHi: "0",
                userAuthClaimNonRevMtpAuxHv: "0",
                userAuthClaimNonRevMtpNoAux: "1",
                challenge: "1",
                challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
                challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
                challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
                userClaimsTreeRoot: "9763429684850732628215303952870004997159843236039795272605841029866455670219",
                userRevTreeRoot: "0",
                userRootsTreeRoot: "0",
                userState: "18656147546666944484453899241916469544090258810192803949522794490493271005313",
                globalSmtRoot: "13891407091237035626910338386637210028103224489833886255774452947213913989795",
                globalSmtMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
                globalSmtMtpAuxHi: "321655963459726004040127369337727353299407142334036950741528344494565949440",
                globalSmtMtpAuxHv: "1257746809182882563786560928809910818663538703587513060503018952434273712929",
                globalSmtMtpNoAux: "0",
            },
            output: {
                userID: "86673097869291892577577670655095803058458914610818194234435166934839525376",
                challenge: "1",
                globalSmtRoot: "13891407091237035626910338386637210028103224489833886255774452947213913989795",

            },
        },
    ];

    let circuit;
    this.timeout(300000)

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits", "authV2Test.circom"),
            {
                output: path.join(__dirname, "../circuits", "build/authV2"),
                recompile: true,
                reduceConstraints: false,
            },
        );
    });

    tests.forEach(({desc, input, output}) => {
        it(`auth ${desc}`, async function() {
            const w = await circuit.calculateWitness(input, true);
            await circuit.checkConstraints(w);
            await circuit.assertOut(w, output);
        });
    });
});
