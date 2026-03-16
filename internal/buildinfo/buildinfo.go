package buildinfo

import "strings"

var (
	Version = ""
	Commit  = ""
)

// Release returns build metadata injected during compilation.
func Release() string {
	version := strings.TrimSpace(Version)
	commit := strings.TrimSpace(Commit)

	switch {
	case version != "" && commit != "":
		return version + "+" + shortCommit(commit)
	case version != "":
		return version
	case commit != "":
		return shortCommit(commit)
	default:
		return ""
	}
}

func shortCommit(commit string) string {
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}
