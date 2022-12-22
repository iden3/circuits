package sybil

import "testing"

func TestHappyFlowMTP(t *testing.T) {

	desc := "Sybil resistance - Happy flow - MTP"

	generateTestDataMTP(t, desc, "happyflow - MTP")
}

func TestHappyFlowSig(t *testing.T) {

	desc := "Sybil resistance - Happy flow - Sig"

	generateTestDataSig(t, desc, "happyflow - Sig")
}
