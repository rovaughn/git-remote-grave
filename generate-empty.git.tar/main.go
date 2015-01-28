// This script create an empty git repo, packs it using the grave/tarpack
// package, and emits the output to empty.git.  empty.git is then used
// by git-remote-grave as the dictionary for compressing and decompressing,
// which reduces the size of compressed git archives by a lot.
//
// Because it's important that empty.git remain identical across builds
// for compatibility, it's been checked into the repository, but this
// script remains to document how it was generated.

package main

import (
	"fmt"
	"grave/tarpack"
	"io"
	"os"
	"os/exec"
)

func Fatal(a ...interface{}) {
	fmt.Println(a...)
	os.Exit(1)
}

func main() {
	if err := exec.Command("git", "init", "emptyrepo").Run(); err != nil {
		Fatal(err)
	}

	packer := tarpack.NewPacker("emptyrepo", ".git")

	file, err := os.Create("empty.git.tar")
	if err != nil {
		Fatal(err)
	}
	defer file.Close()

	if _, err := io.Copy(file, packer); err != nil {
		Fatal(err)
	}
}
