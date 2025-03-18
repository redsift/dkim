module github.com/redsift/dkim

go 1.24

require (
	github.com/google/go-cmp v0.6.0
	github.com/stretchr/testify v1.4.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/pkg/diff v0.0.0-20210226163009-20ebb0f2a09e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tailscale/depaware v0.0.0-20250112153213-b748de04d81b // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	honnef.co/go/tools v0.6.1 // indirect
	mvdan.cc/gofumpt v0.7.0 // indirect
)

tool (
	github.com/tailscale/depaware/depaware
	honnef.co/go/tools/cmd/staticcheck
	mvdan.cc/gofumpt
)
