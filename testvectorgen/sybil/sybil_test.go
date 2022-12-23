package sybil

import "testing"

func TestHappyFlowMTP(t *testing.T) {
	desc := "Sybil resistance - Happy flow - MTP"
	generateTestDataMTP(t, desc, "happyflow - MTP", false, false, false, false)
}

func TestHappyFlowSig(t *testing.T) {
	desc := "Sybil resistance - Happy flow - Sig"
	generateTestDataSig(t, desc, "happyflow - Sig", false, false, false, false)
}

func TestInvalidGistRootMTP(t *testing.T) {
	desc := "Sybil resistance - Invalid GIST Root - MTP"
	generateTestDataMTP(t, desc, "invalid gist - MTP", true, false, false, false)
}

func TestInvalidGistRootSig(t *testing.T) {
	desc := "Sybil resistance - Invalid GIST Root - Sig"
	generateTestDataSig(t, desc, "invalid gist - Sig", true, false, false, false)
}

func TestInvalidIdentitySig(t *testing.T) {
	desc := "Sybil resistance - Invalid Identity - Sig"
	generateTestDataSig(t, desc, "invalid identity - Sig", false, true, false, false)
}

func TestInvalidIdentityMTP(t *testing.T) {
	desc := "Sybil resistance - Invalid Identity - MTP"
	generateTestDataMTP(t, desc, "invalid identity - MTP", false, true, false, false)
}

func TestHappyFlowWithProfileMTP(t *testing.T) {
	desc := "Sybil resistance - Happy flow with Profile - MTP"
	generateTestDataMTP(t, desc, "happyflow with profile - MTP", false, false, true, false)
}

func TestHappyFlowWithProfileSig(t *testing.T) {
	desc := "Sybil resistance - Happy flow with Profile - Sig"
	generateTestDataSig(t, desc, "happyflow with profile - Sig", false, false, true, false)
}

func TestHappyFlowWithProfileAndSubjectMTP(t *testing.T) {
	desc := "Sybil resistance - Happy flow with Profile and Subject - MTP"
	generateTestDataMTP(t, desc, "happyflow with profile and subject - MTP", false, false, true, true)
}

func TestHappyFlowWithProfileAndSubjectSig(t *testing.T) {
	desc := "Sybil resistance - Happy flow with Profile and Subject - Sig"
	generateTestDataSig(t, desc, "happyflow with profile and subject - Sig", false, false, true, true)
}
