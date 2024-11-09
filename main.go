package main

import (
	_ "embed"
	"github.com/shanhai-repository/createrepo_go/cmd"
)

//go:generate sh -c "make -s version | tr -d '\n' > VERSION"
//go:embed VERSION
var Version string

func main() {
	cmd.Version = Version
	cmd.Execute()
}
