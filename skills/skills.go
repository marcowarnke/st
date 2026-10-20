// Package skills embeds the agent skills shipped with st, so
// `st skills install` always installs the ones matching the binary.
package skills

import "embed"

//go:embed */SKILL.md
var FS embed.FS
