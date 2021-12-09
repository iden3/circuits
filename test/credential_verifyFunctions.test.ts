const path = require("path");
const tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

const verifyCredentialSubject = {
    claim: [
        "700576110560149417265602648140262015232",
        "197990912273762023075897629417744831667514652778362723486029975898079821824",
        "0",
        "0",
        "123",
        "0",
        "0",
        "0",
    ],
    id: "197990912273762023075897629417744831667514652778362723486029975898079821824", // 117twYCgGzxHUtMsAfjM3muCrypTXcu6oc7cSsuGHM
}

describe("credential verifyCredentialSubject test", function () {
    this.timeout(200000);
    it("Test credential verifyCredentialSubject", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "credential_verifyCredentialSubject.circom"),
            {reduceConstraints: false},
        );

        const witness = await circuit.calculateWitness(verifyCredentialSubject, true);
        await circuit.checkConstraints(witness);
    });
});

const verifyCredentialMtp = {
    "claim": [
        "20654715993900013474510316175425517108417418890313728",
        "40727245799613559019751726539717406914187024287975587258911930442547331072",
        "0",
        "0",
        "3422259402",
        "0",
        "0",
        "0"
    ],
    "isProofExistMtp": [
        "8642944718030808750631174116590545595346699877855966554837410767850901050241",
        "0",
        "2559121857990624749645748723611740625389471552768523819941100032832108291070",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0"
    ],
    "isProofExistClaimsTreeRoot": "8983046041355403090199265671506633595311694354613197795337389712944858482798"
}

describe("credential verifyCredentialMtp test", function () {
    this.timeout(200000);
    it("Test credential verifyCredentialMtp", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "credential_verifyCredentialMtp.circom"),
            //{reduceConstraints: false},
        );

        const witness = await circuit.calculateWitness(verifyCredentialMtp, true);
        await circuit.checkConstraints(witness);
    });
});

describe("credential verifyIdenStateMatchesRoots test", function () {
    this.timeout(200000);
    it("Test credential verifyIdenStateMatchesRoots", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "credential_verifyIdenStateMatchesRoots.circom"),
            //{reduceConstraints: false},
        );

        const witness = await circuit.calculateWitness({
            "isProofValidClaimsTreeRoot": "5390978791160263927985161830452830346003784422812143177724675599288112176057",
            "isProofValidRevTreeRoot": "0",
            "isProofValidRootsTreeRoot": "0",
            "isIdenState": "17685575544241839934776615609352503109564813484662571173826983469932580732343"
        }, true);
        await circuit.checkConstraints(witness);
    });
});

describe("credential verifyClaimSignature test", function () {
    this.timeout(200000);
    it("Test credential verifyClaimSignature", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "credential_verifyClaimSignature.circom"),
            //{reduceConstraints: false},
        );

        const witness = await circuit.calculateWitness({
            "claim": ["0","0","0","0","0","0","0","0"],
            "sigR8x": "9813265844413837380082826071463892301278045128546516139211810884421030840917",
            "sigR8y": "7110066446166689493462986682910785889642607369745074815971396692733663407188",
            "sigS": "1837652275043347007743363280039859735198580922853822340283578942174886737707",
            "pubKeyX": "11356572759147270709631238494624398626863089762419266085446886102966874017086",
            "pubKeyY": "6952793560627676182867513788009876275064024476317357446458237628508619978750"
        }, true);
        await circuit.checkConstraints(witness);
    });
});
