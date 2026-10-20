package main

import (
	"os"

	"github.com/marcowarnke/st/internal/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
