module test

go 1.17

replace github.com/iden3/go-iden3-core => ../../../go-iden3-core

require (
	github.com/iden3/go-iden3-core v0.1.1-0.20221025125203-647bfb3a986a
	github.com/iden3/go-iden3-crypto v0.0.13
	github.com/iden3/go-merkletree-sql v1.0.1
	github.com/iden3/go-schema-processor v0.1.1-0.20221027144311-67064a324256
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/piprate/json-gold v0.4.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	golang.org/x/crypto v0.0.0-20220126234351-aa10faf2a1f8 // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
