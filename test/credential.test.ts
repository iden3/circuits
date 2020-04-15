const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const chai = require("chai");
const assert = chai.assert;

export {};

describe("credential test", function () {
    this.timeout(200000);


    it("Test Credential simple tree", async () => {
        const compiledCircuit = await compiler(
            path.join(__dirname, "circuits", "credential-simpletree.circom"),
            { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        // input data generated with circuits/test/testvectorsgen/credential_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            issuerRoot: "20345323600276915334840455511884465229803859322011240311319051873466365756230",
            mtp: ["0", "0", "0", "0"],
            id: "418819843184716391854950027336187830212226236089582432322628806588929540096",
            oUserPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            oMtp: ["0", "0", "0", "0"],
            oClaimsTreeRoot: "19759495200350784025545259483378281480848861021788190330947710448581962628389",
            oRevTreeRoot: "0",
            oRootsTreeRoot: "4993494596562389383889749727008725160160552507022773815483402975297010560970"
        });
        assert(circuit.checkWitness(witness));
    });

    it("Test Credential crowded tree", async () => {
        const compiledCircuit = await compiler(
            path.join(__dirname, "circuits", "credential-crowdedtree.circom"),
            { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        // input data generated with circuits/testvectorsgen/credential_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            issuerRoot: "15797803252728443209616381990433131096640537982070147713338175380570298454976",
            mtp: ["0","0","13916889557215241228015141713364344747865487575761466027104065750914992601361","0","1690755171476910509239176159009614851908078886245570023216111461801296009507","0","0","0","0","0","0"],
            id: "418819843184716391854950027336187830212226236089582432322628806588929540096",
            oUserPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            oMtp: ["0", "0", "0", "0"],
            oClaimsTreeRoot: "19759495200350784025545259483378281480848861021788190330947710448581962628389",
            oRevTreeRoot: "0",
            oRootsTreeRoot: "4993494596562389383889749727008725160160552507022773815483402975297010560970"
        });
        assert(circuit.checkWitness(witness));
    });

    it("Test Credential crowded tree 2", async () => {
        const compiledCircuit = await compiler(
            path.join(__dirname, "circuits", "credential-crowdedtree.circom"),
            { reduceConstraints: false }
        );
        const circuit = new snarkjs.Circuit(compiledCircuit);

        // input data generated with circuits/testvectorsgen/credential_test.go, which uses go-iden3-core
        const witness = circuit.calculateWitness({
            issuerRoot: "2129482215913584500569008537045904456845658748821359635806813662925761769886",
            mtp: ["604188087829632076306376825067769041242138923320155729340326180965998292587","17718355220464227213288151505646534046014097853894322131890418720614087460956","2252100485810221620724624245977333650139249675725008098218121781589002804416","0","1690755171476910509239176159009614851908078886245570023216111461801296009507","0","0","0","0","0","0"],
            id: "418819843184716391854950027336187830212226236089582432322628806588929540096",
            oUserPrivateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            oMtp: ["0", "0", "0", "0"],
            oClaimsTreeRoot: "19759495200350784025545259483378281480848861021788190330947710448581962628389",
            oRevTreeRoot: "0",
            oRootsTreeRoot: "4993494596562389383889749727008725160160552507022773815483402975297010560970"
        });
        assert(circuit.checkWitness(witness));
    });

});
