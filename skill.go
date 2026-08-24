// Package snykcli embeds the repository's agent skill so the binary can
// install it anywhere without network access; the embedded copy is the
// source of truth at each build, so binary and skill stay version-matched.
package snykcli

import _ "embed"

//go:embed skills/snyk/SKILL.md
var SkillMD string
