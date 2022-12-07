//go:build for_go_mod_tidy_only

package tooldeps

import (
	_ "github.com/tailscale/depaware/depaware"
	_ "honnef.co/go/tools/cmd/staticcheck"
	_ "mvdan.cc/gofumpt"
)
