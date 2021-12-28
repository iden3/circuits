module constants

go 1.14

require (
	github.com/ethereum/go-ethereum v1.10.8 // indirect
	github.com/iden3/go-circom-prover-verifier v0.0.1
	github.com/iden3/go-iden3-core v0.0.8
	github.com/iden3/go-iden3-crypto v0.0.6
	github.com/iden3/go-merkletree-sql v1.0.0-pre5
	github.com/mitchellh/mapstructure v1.3.0
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.7.0
)

replace github.com/iden3/go-iden3-core => ../../go-iden3-core

replace github.com/iden3/go-iden3-crypto => ../../go-iden3-crypto

replace github.com/iden3/go-merkletree-sql => ../../go-merkletree-sql
