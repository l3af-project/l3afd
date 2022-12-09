package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
)

var (
	// Version binary version number
	Version string = "0.0.0"
	// SuffixTag binary tag (e.g. beta, dev, devel, production).
	SuffixTag string
	// VersionDate build timestamp (e.g. ).
	VersionDate string
	// VersionSHA git commit SHA.
	VersionSHA string

	versionFlag = flag.Bool("version", false, "display version information")
)

// Init prints version information and exits, if --version option passed.
func initVersion() {
	if *versionFlag {
		fmt.Println(VersionInfo())
		os.Exit(0)
	}
}

// VersionInfo returns a formatted string of version data used in the version flag.
func VersionInfo() string {
	var sha, buildDate string
	if btime, err := time.Parse("20060102150405", VersionDate); err == nil {
		buildDate = "built " + btime.Format(time.RFC3339)
	} else {
		currentFilePath, err := os.Executable()
		if err == nil {
			info, err := os.Stat(currentFilePath)
			if err == nil {
				buildDate = info.ModTime().Format(time.RFC3339)
			}
		}
	}

	if VersionSHA != "" {
		sha = "\nBuild SHA: " + VersionSHA
	}

	return fmt.Sprintf("Version: %s\nGo Version: %s\nBuild Date: %s%s", ShortVersion(), runtime.Version(), buildDate, sha)
}

// ShortVersion returns a formatted string containing only the Version and VersionTag
func ShortVersion() string {
	if Version == "0.0.0" {
		SuffixTag = "dev"
	}
	if SuffixTag != "" {
		return fmt.Sprintf("%s-%s", Version, SuffixTag)
	}
	return Version
}
