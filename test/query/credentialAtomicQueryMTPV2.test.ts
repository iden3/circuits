import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;
const chai = require("chai");
const expect = chai.expect;

describe("Test credentialAtomicQueryMTPV2.circom", function() {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../../circuits/offchain", "credentialAtomicQueryMTPV2.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

    });

    after(async () => {
        circuit.release()
    })

    const tests = [
        {desc: "User != Subject. Claim issued on ProfileID", inputs: {requestID: "23", userGenesisID: "19104853439462320209059061537253618984153217267677512271018416655565783041", nonce: "0", claimSubjectProfileNonce: "999", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaim: ["14472269431592746875347367665757389417422", "25927604890613122427738740609000473205690959612845229713851180119865819137", "17568057213828477233507447080689055308823020388972334380526849356111335110900", "0", "30803922965249841627828060170", "0", "0", "0"], issuerClaimMtp: ["0", "20705360459443886266589173521200199826970601318029396875976898748762842059297", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimClaimsTreeRoot: "17517135754166266461911626374128443345742297668454840746934089624003967135226", issuerClaimRevTreeRoot: "0", issuerClaimRootsTreeRoot: "0", issuerClaimIdenState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", issuerClaimNonRevClaimsTreeRoot: "17517135754166266461911626374128443345742297668454840746934089624003967135226", issuerClaimNonRevRevTreeRoot: "0", issuerClaimNonRevRootsTreeRoot: "0", issuerClaimNonRevState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", issuerClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimNonRevMtpAuxHi: "0", issuerClaimNonRevMtpAuxHv: "0", issuerClaimNonRevMtpNoAux: "1", claimSchema: "180410020913331409885634153623124536270", claimPathNotExists: "0", claimPathMtp: ["5559250731000753554753485016695600829384855452867544273344893815961938985436", "20222899544143787877985297439625828822272100269106711904511119118819809140477", "14730426618666280941604039095550905490156541514901979358549599762282042588641", "20497288520738821800886677250569208588689763166335933087499619993954968899866", "3295720551404287572425718873751040314503774617833462052445584373469655789999", "796356776410152646380783209242693344675665178494017735650545708722024766291", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], claimPathMtpNoAux: "0", claimPathMtpAuxHi: "0", claimPathMtpAuxHv: "0", claimPathKey: "8566939875427719562376598811066985304309117528846759529734201066483458512800", claimPathValue: "1420070400000000000", operator: 1, slotIndex: 0, timestamp: "1642074362", value: ["1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]}, expOut: {requestID: "23", userID: "19104853439462320209059061537253618984153217267677512271018416655565783041", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaimIdenState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", issuerClaimNonRevState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", claimSchema: "180410020913331409885634153623124536270", slotIndex: "0", operator: 1, value: ["1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], timestamp: "1642074362", merklized: "1", claimPathKey: "8566939875427719562376598811066985304309117528846759529734201066483458512800", claimPathNotExists: "0"}},
        {desc: "User == Subject. Claim issued on ProfileID", inputs: {requestID: "23", userGenesisID: "19104853439462320209059061537253618984153217267677512271018416655565783041", nonce: "10", claimSubjectProfileNonce: "999", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaim: ["14472269431592746875347367665757389417422", "25927604890613122427738740609000473205690959612845229713851180119865819137", "17568057213828477233507447080689055308823020388972334380526849356111335110900", "0", "30803922965249841627828060170", "0", "0", "0"], issuerClaimMtp: ["0", "20705360459443886266589173521200199826970601318029396875976898748762842059297", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimClaimsTreeRoot: "17517135754166266461911626374128443345742297668454840746934089624003967135226", issuerClaimRevTreeRoot: "0", issuerClaimRootsTreeRoot: "0", issuerClaimIdenState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", issuerClaimNonRevClaimsTreeRoot: "17517135754166266461911626374128443345742297668454840746934089624003967135226", issuerClaimNonRevRevTreeRoot: "0", issuerClaimNonRevRootsTreeRoot: "0", issuerClaimNonRevState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", issuerClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimNonRevMtpAuxHi: "0", issuerClaimNonRevMtpAuxHv: "0", issuerClaimNonRevMtpNoAux: "1", claimSchema: "180410020913331409885634153623124536270", claimPathNotExists: "0", claimPathMtp: ["5559250731000753554753485016695600829384855452867544273344893815961938985436", "20222899544143787877985297439625828822272100269106711904511119118819809140477", "14730426618666280941604039095550905490156541514901979358549599762282042588641", "20497288520738821800886677250569208588689763166335933087499619993954968899866", "3295720551404287572425718873751040314503774617833462052445584373469655789999", "796356776410152646380783209242693344675665178494017735650545708722024766291", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], claimPathMtpNoAux: "0", claimPathMtpAuxHi: "0", claimPathMtpAuxHv: "0", claimPathKey: "8566939875427719562376598811066985304309117528846759529734201066483458512800", claimPathValue: "1420070400000000000", operator: 1, slotIndex: 0, timestamp: "1642074362", value: ["1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]}, expOut: {requestID: "23", userID: "25488971158629062708211589022720088934000314791497875911489989686829383681", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaimIdenState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", issuerClaimNonRevState: "2438933745891896800844926295828866006295479853528709648445321995991664607327", claimSchema: "180410020913331409885634153623124536270", slotIndex: "0", operator: 1, value: ["1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], timestamp: "1642074362", merklized: "1", claimPathKey: "8566939875427719562376598811066985304309117528846759529734201066483458512800", claimPathNotExists: "0"}},
        {desc: "User == Subject. Claim issued on UserID", inputs: {requestID: "23", userGenesisID: "19104853439462320209059061537253618984153217267677512271018416655565783041", nonce: "0", claimSubjectProfileNonce: "0", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaim: ["14472269431592746875347367665757389417422", "19104853439462320209059061537253618984153217267677512271018416655565783041", "17568057213828477233507447080689055308823020388972334380526849356111335110900", "0", "30803922965249841627828060170", "0", "0", "0"], issuerClaimMtp: ["0", "20705360459443886266589173521200199826970601318029396875976898748762842059297", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimClaimsTreeRoot: "10745697386530312321282981424857934118239635163154393224283223656792351141641", issuerClaimRevTreeRoot: "0", issuerClaimRootsTreeRoot: "0", issuerClaimIdenState: "16795175361730581522577750003519846283406021008296781015998552782923927317040", issuerClaimNonRevClaimsTreeRoot: "10745697386530312321282981424857934118239635163154393224283223656792351141641", issuerClaimNonRevRevTreeRoot: "0", issuerClaimNonRevRootsTreeRoot: "0", issuerClaimNonRevState: "16795175361730581522577750003519846283406021008296781015998552782923927317040", issuerClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimNonRevMtpAuxHi: "0", issuerClaimNonRevMtpAuxHv: "0", issuerClaimNonRevMtpNoAux: "1", claimSchema: "180410020913331409885634153623124536270", claimPathNotExists: "0", claimPathMtp: ["5559250731000753554753485016695600829384855452867544273344893815961938985436", "20222899544143787877985297439625828822272100269106711904511119118819809140477", "14730426618666280941604039095550905490156541514901979358549599762282042588641", "20497288520738821800886677250569208588689763166335933087499619993954968899866", "3295720551404287572425718873751040314503774617833462052445584373469655789999", "796356776410152646380783209242693344675665178494017735650545708722024766291", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], claimPathMtpNoAux: "0", claimPathMtpAuxHi: "0", claimPathMtpAuxHv: "0", claimPathKey: "8566939875427719562376598811066985304309117528846759529734201066483458512800", claimPathValue: "1420070400000000000", operator: 1, slotIndex: 0, timestamp: "1642074362", value: ["1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]}, expOut: {requestID: "23", userID: "19104853439462320209059061537253618984153217267677512271018416655565783041", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaimIdenState: "16795175361730581522577750003519846283406021008296781015998552782923927317040", issuerClaimNonRevState: "16795175361730581522577750003519846283406021008296781015998552782923927317040", claimSchema: "180410020913331409885634153623124536270", slotIndex: "0", operator: 1, value: ["1420070400000000000", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], timestamp: "1642074362", merklized: "1", claimPathKey: "8566939875427719562376598811066985304309117528846759529734201066483458512800", claimPathNotExists: "0"}},
        {desc: "User == Subject. Claim non merklized claim", inputs: {requestID: "23", userGenesisID: "19104853439462320209059061537253618984153217267677512271018416655565783041", nonce: "0", claimSubjectProfileNonce: "0", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaim: ["3583233690122716044519380227940806650830", "19104853439462320209059061537253618984153217267677512271018416655565783041", "10", "0", "30803922965249841627828060161", "0", "0", "0"], issuerClaimMtp: ["0", "0", "0", "0", "20705360459443886266589173521200199826970601318029396875976898748762842059297", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimClaimsTreeRoot: "4291331108778058814748735252751774985133130667958634779040926608237236193887", issuerClaimRevTreeRoot: "0", issuerClaimRootsTreeRoot: "0", issuerClaimIdenState: "5687720250943511874245715094520098014548846873346473635855112185560372332782", issuerClaimNonRevClaimsTreeRoot: "4291331108778058814748735252751774985133130667958634779040926608237236193887", issuerClaimNonRevRevTreeRoot: "0", issuerClaimNonRevRootsTreeRoot: "0", issuerClaimNonRevState: "5687720250943511874245715094520098014548846873346473635855112185560372332782", issuerClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], issuerClaimNonRevMtpAuxHi: "0", issuerClaimNonRevMtpAuxHv: "0", issuerClaimNonRevMtpNoAux: "1", claimSchema: "180410020913331409885634153623124536270", claimPathNotExists: "0", claimPathMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], claimPathMtpNoAux: "0", claimPathMtpAuxHi: "0", claimPathMtpAuxHv: "0", claimPathKey: "0", claimPathValue: "0", operator: 1, slotIndex: 2, timestamp: "1642074362", value: ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]}, expOut: {requestID: "23", userID: "19104853439462320209059061537253618984153217267677512271018416655565783041", issuerID: "23528770672049181535970744460798517976688641688582489375761566420828291073", issuerClaimIdenState: "5687720250943511874245715094520098014548846873346473635855112185560372332782", issuerClaimNonRevState: "5687720250943511874245715094520098014548846873346473635855112185560372332782", claimSchema: "180410020913331409885634153623124536270", slotIndex: "2", operator: 1, value: ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"], timestamp: "1642074362", merklized: "0", claimPathKey: "0", claimPathNotExists: "0"}},
        {"desc":"User's claim revoked and the circuit not checking for revocation status (expected to fail)","inputs":{"userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","nonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["3583233690122716044519380227940806650830","19104853439462320209059061537253618984153217267677512271018416655565783041","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimMtp":["0","0","0","0","20705360459443886266589173521200199826970601318029396875976898748762842059297","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimClaimsTreeRoot":"4291331108778058814748735252751774985133130667958634779040926608237236193887","issuerClaimRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerClaimRootsTreeRoot":"0","issuerClaimIdenState":"6344923704725747138709470083565649368088034914458130592289968871891196214095","isRevocationChecked":0,"issuerClaimNonRevClaimsTreeRoot":"4291331108778058814748735252751774985133130667958634779040926608237236193887","issuerClaimNonRevRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"6344923704725747138709470083565649368088034914458130592289968871891196214095","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"0","claimSchema":"180410020913331409885634153623124536270","claimPathNotExists":"0","claimPathMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"0","claimPathValue":"0","operator":1,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"19104853439462320209059061537253618984153217267677512271018416655565783041","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaimIdenState":"6344923704725747138709470083565649368088034914458130592289968871891196214095","issuerClaimNonRevState":"6344923704725747138709470083565649368088034914458130592289968871891196214095","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"0","claimPathKey":"0","claimPathNotExists":"0"}},
   ];

    tests.forEach(({desc, inputs, expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });

    it("Checking revoked status when claim is revoked (MTP)", async () => {
        const inputs = {"userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","nonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["3583233690122716044519380227940806650830","19104853439462320209059061537253618984153217267677512271018416655565783041","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimMtp":["0","0","0","0","20705360459443886266589173521200199826970601318029396875976898748762842059297","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimClaimsTreeRoot":"4291331108778058814748735252751774985133130667958634779040926608237236193887","issuerClaimRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerClaimRootsTreeRoot":"0","issuerClaimIdenState":"6344923704725747138709470083565649368088034914458130592289968871891196214095","isRevocationChecked":1,"issuerClaimNonRevClaimsTreeRoot":"4291331108778058814748735252751774985133130667958634779040926608237236193887","issuerClaimNonRevRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"6344923704725747138709470083565649368088034914458130592289968871891196214095","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"0","claimSchema":"180410020913331409885634153623124536270","claimPathNotExists":"0","claimPathMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"0","claimPathValue":"0","operator":1,"slotIndex":2,"timestamp":"1642074362","value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]}

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error.message).to.include("Error in template checkClaimNotRevoked");
    });

});
