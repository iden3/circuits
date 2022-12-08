import {describe} from "mocha";

const path = require("path");
const wasmTester = require("circom_tester").wasm;
const chai = require("chai");
const expect = chai.expect;

describe("Test credentialAtomicQuerySigV2.circom", function() {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "../../circuits/offchain", "credentialAtomicQuerySigV2.circom"),
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
        {"desc":"JSON-LD proof non inclusion. UserID = Subject. UserID out. User nonce = 0, Subject nonce = 0 claim issued on userID (Merklized claim)","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["14472269431592746875347367665757389417422","19104853439462320209059061537253618984153217267677512271018416655565783041","17568057213828477233507447080689055308823020388972334380526849356111335110900","0","30803922965249841627828060170","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"14766467944434267027977074773942452286531721119040212570813936329795945360642","issuerClaimSignatureR8y":"13177025784752378311061376541674096993071825903834397324335793638711439230739","issuerClaimSignatureS":"1899358263334042751297934787511989214605059024958998751090095249889443746119","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"1","claimPathMtp":["5559250731000753554753485016695600829384855452867544273344893815961938985436","8572801910485227983539995488533475408768322385604766084351333237918158876183","0","21558280644890495634574226008223308568148491750171125081160458621552477288821","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"15924483770554419123485443865253852621108414928056512791337538323107671760706","claimPathMtpAuxHv":"3649436878755004634629983548864752783389248075618975309339506929996626029578","claimPathKey":"4565618812218816904592638866963205946316329857551756884889133933625594842882","claimPathValue":"0","operator":0,"slotIndex":0,"timestamp":"1642074362","isRevocationChecked":1,"value":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"19104853439462320209059061537253618984153217267677512271018416655565783041","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","claimSchema":"180410020913331409885634153623124536270","slotIndex":"0","operator":0,"value":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"1","claimPathNotExists":"1"}},
        {"desc":"UserID != Subject. UserID out. User nonce = 0. Claim issued on Profile (subject nonce = 999) (Merklized claim)","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"0","claimSubjectProfileNonce":"999","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["14472269431592746875347367665757389417422","25927604890613122427738740609000473205690959612845229713851180119865819137","17568057213828477233507447080689055308823020388972334380526849356111335110900","0","30803922965249841627828060170","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"14737735628637311623213166240308046419633555308599869434166445385883754185248","issuerClaimSignatureR8y":"5303209968035777820125690469632427047553223182959970343667962629702974291553","issuerClaimSignatureS":"1321243788532174332352653681249497588283350120894923264282719287309014014827","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["5559250731000753554753485016695600829384855452867544273344893815961938985436","20222899544143787877985297439625828822272100269106711904511119118819809140477","14730426618666280941604039095550905490156541514901979358549599762282042588641","20497288520738821800886677250569208588689763166335933087499619993954968899866","3295720551404287572425718873751040314503774617833462052445584373469655789999","796356776410152646380783209242693344675665178494017735650545708722024766291","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"8566939875427719562376598811066985304309117528846759529734201066483458512800","claimPathValue":"1420070400000000000","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"19104853439462320209059061537253618984153217267677512271018416655565783041","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"1","claimPathNotExists":"0"}},
        {"desc":"UserID == Subject. UserProfile out. User nonce = 10. Claim issued on Profile (subject nonce = 999) (Merklized claim)","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"10","claimSubjectProfileNonce":"999","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["14472269431592746875347367665757389417422","25927604890613122427738740609000473205690959612845229713851180119865819137","17568057213828477233507447080689055308823020388972334380526849356111335110900","0","30803922965249841627828060170","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"14737735628637311623213166240308046419633555308599869434166445385883754185248","issuerClaimSignatureR8y":"5303209968035777820125690469632427047553223182959970343667962629702974291553","issuerClaimSignatureS":"1321243788532174332352653681249497588283350120894923264282719287309014014827","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["5559250731000753554753485016695600829384855452867544273344893815961938985436","20222899544143787877985297439625828822272100269106711904511119118819809140477","14730426618666280941604039095550905490156541514901979358549599762282042588641","20497288520738821800886677250569208588689763166335933087499619993954968899866","3295720551404287572425718873751040314503774617833462052445584373469655789999","796356776410152646380783209242693344675665178494017735650545708722024766291","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"8566939875427719562376598811066985304309117528846759529734201066483458512800","claimPathValue":"1420070400000000000","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"25488971158629062708211589022720088934000314791497875911489989686829383681","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"1","claimPathNotExists":"0"}},
        {"desc":"UserID != Subject. UserProfile out. User nonce = 10. Claim issued on Profile (subject nonce = 0) (Merklized claim)","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"10","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["14472269431592746875347367665757389417422","19104853439462320209059061537253618984153217267677512271018416655565783041","17568057213828477233507447080689055308823020388972334380526849356111335110900","0","30803922965249841627828060170","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"14766467944434267027977074773942452286531721119040212570813936329795945360642","issuerClaimSignatureR8y":"13177025784752378311061376541674096993071825903834397324335793638711439230739","issuerClaimSignatureS":"1899358263334042751297934787511989214605059024958998751090095249889443746119","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["5559250731000753554753485016695600829384855452867544273344893815961938985436","20222899544143787877985297439625828822272100269106711904511119118819809140477","14730426618666280941604039095550905490156541514901979358549599762282042588641","20497288520738821800886677250569208588689763166335933087499619993954968899866","3295720551404287572425718873751040314503774617833462052445584373469655789999","796356776410152646380783209242693344675665178494017735650545708722024766291","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"8566939875427719562376598811066985304309117528846759529734201066483458512800","claimPathValue":"1420070400000000000","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"25488971158629062708211589022720088934000314791497875911489989686829383681","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"1","claimPathNotExists":"0"}},
        {"desc":"UserID == Subject. UserID out. User nonce = 0, Subject nonce = 0 claim issued on userID (Claim)","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["3583233690122716044519380227940806650830","19104853439462320209059061537253618984153217267677512271018416655565783041","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"17162142911607569076910858896898912994773523663650479471952820383079910930699","issuerClaimSignatureR8y":"15051201438059790575397440686723091111368657477685528398200371392585350837738","issuerClaimSignatureS":"1402447066943664601187351107413084496053664373012210278526422113191686989197","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"0","claimPathValue":"0","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":1,"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"19104853439462320209059061537253618984153217267677512271018416655565783041","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"0","claimPathNotExists":"0"}},
        {"desc":"UserID = Subject. UserID out. User nonce = 0, Subject nonce = 0 claim issued on userID (Merklized claim)","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["14472269431592746875347367665757389417422","19104853439462320209059061537253618984153217267677512271018416655565783041","17568057213828477233507447080689055308823020388972334380526849356111335110900","0","30803922965249841627828060170","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"0","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"1","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"14766467944434267027977074773942452286531721119040212570813936329795945360642","issuerClaimSignatureR8y":"13177025784752378311061376541674096993071825903834397324335793638711439230739","issuerClaimSignatureS":"1899358263334042751297934787511989214605059024958998751090095249889443746119","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"0","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"1","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"0","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["5559250731000753554753485016695600829384855452867544273344893815961938985436","20222899544143787877985297439625828822272100269106711904511119118819809140477","14730426618666280941604039095550905490156541514901979358549599762282042588641","20497288520738821800886677250569208588689763166335933087499619993954968899866","3295720551404287572425718873751040314503774617833462052445584373469655789999","796356776410152646380783209242693344675665178494017735650545708722024766291","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"8566939875427719562376598811066985304309117528846759529734201066483458512800","claimPathValue":"1420070400000000000","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"19104853439462320209059061537253618984153217267677512271018416655565783041","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","issuerClaimNonRevState":"12035569423371053239461605003190702990928630784475264346060457607843543656590","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["1420070400000000000","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"1","claimPathNotExists":"0"}},
        {"desc":"User's claim revoked and the circuit not checking for revocation status","inputs":{"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["3583233690122716044519380227940806650830","19104853439462320209059061537253618984153217267677512271018416655565783041","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"5696433109178441527170923154674356132379950969763509474993514267314807821397","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"0","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"17162142911607569076910858896898912994773523663650479471952820383079910930699","issuerClaimSignatureR8y":"15051201438059790575397440686723091111368657477685528398200371392585350837738","issuerClaimSignatureS":"1402447066943664601187351107413084496053664373012210278526422113191686989197","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"1","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"0","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"0","claimPathValue":"0","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":0,"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]},"expOut":{"userID":"19104853439462320209059061537253618984153217267677512271018416655565783041","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerAuthState":"5696433109178441527170923154674356132379950969763509474993514267314807821397","issuerClaimNonRevState":"5696433109178441527170923154674356132379950969763509474993514267314807821397","claimSchema":"180410020913331409885634153623124536270","slotIndex":"2","operator":1,"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"timestamp":"1642074362","merklized":"0","claimPathNotExists":"0"}},
    ];

    tests.forEach(({desc, inputs, expOut}) => {
        it(`${desc}`, async function() {
            const w = await circuit.calculateWitness(inputs, true);
            await circuit.assertOut(w, expOut);
            await circuit.checkConstraints(w);
        });
    });



    it("Checking revoked status when claim is revoked (Sig)", async () => {
        const inputs = {"requestID": "23", "userGenesisID":"19104853439462320209059061537253618984153217267677512271018416655565783041","profileNonce":"0","claimSubjectProfileNonce":"0","issuerID":"23528770672049181535970744460798517976688641688582489375761566420828291073","issuerClaim":["3583233690122716044519380227940806650830","19104853439462320209059061537253618984153217267677512271018416655565783041","10","0","30803922965249841627828060161","0","0","0"],"issuerClaimNonRevClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerClaimNonRevRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerClaimNonRevRootsTreeRoot":"0","issuerClaimNonRevState":"5696433109178441527170923154674356132379950969763509474993514267314807821397","issuerClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerClaimNonRevMtpAuxHi":"0","issuerClaimNonRevMtpAuxHv":"0","issuerClaimNonRevMtpNoAux":"0","claimSchema":"180410020913331409885634153623124536270","issuerClaimSignatureR8x":"17162142911607569076910858896898912994773523663650479471952820383079910930699","issuerClaimSignatureR8y":"15051201438059790575397440686723091111368657477685528398200371392585350837738","issuerClaimSignatureS":"1402447066943664601187351107413084496053664373012210278526422113191686989197","issuerAuthClaim":["301485908906857522017021291028488077057","0","18843627616807347027405965102907494712213509184168391784663804560181782095821","21769574296201138406688395494914474950554632404504713590270198507141791084591","17476719578317212277","0","0","0"],"issuerAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"issuerAuthClaimNonRevMtpAuxHi":"1","issuerAuthClaimNonRevMtpAuxHv":"0","issuerAuthClaimNonRevMtpNoAux":"0","issuerAuthClaimsTreeRoot":"20705360459443886266589173521200199826970601318029396875976898748762842059297","issuerAuthRevTreeRoot":"19374975721259875597650302716689543547647001662517455822229477759190533109280","issuerAuthRootsTreeRoot":"0","claimPathNotExists":"0","claimPathMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"claimPathMtpNoAux":"0","claimPathMtpAuxHi":"0","claimPathMtpAuxHv":"0","claimPathKey":"0","claimPathValue":"0","operator":1,"slotIndex":2,"timestamp":"1642074362","isRevocationChecked":1,"value":["10","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]};

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });
        expect(error.message).to.include("Error in template checkClaimNotRevoked");
    });
});
