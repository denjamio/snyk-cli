package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	embedded "github.com/denjamio/snyk-cli"
	"github.com/denjamio/snyk-cli/internal/output"
)

// runSkill installs (or prints) the SKILL.md embedded in the binary, so the
// skill always travels version-matched with the CLI. Default destination is
// ./.agents/skills in the current project; --global targets ~/.agents and
// --dir overrides both. --print emits the raw markdown instead.
func runSkill(_ context.Context, args []string, s Streams) int {
	cmd, code := parseCommand(skillSpec, args, s)
	if cmd == nil {
		return code
	}
	f := cmd.flags
	switch {
	case len(cmd.positional) > 1:
		return usageError(s, cmd.args, skillSpec.Name, "skill takes at most one positional argument: install")
	case len(cmd.positional) == 1 && cmd.positional[0] != "install":
		return usageError(s, cmd.args, skillSpec.Name, fmt.Sprintf("unexpected argument %q; only the optional action install is accepted", cmd.positional[0]))
	}
	if f.getBool("print") {
		if f.getBool("global") || f.getString("dir") != "" {
			return usageError(s, cmd.args, skillSpec.Name, "--print cannot be combined with a destination")
		}
		fmt.Fprint(s.Out, embedded.SkillMD)
		return 0
	}
	dir := f.getString("dir")
	base := ""
	switch {
	case dir != "":
		base = dir
	case f.getBool("global"):
		home, err := os.UserHomeDir()
		if err != nil {
			return runtimeError(s, cmd.args, "skill", kindInternal, err.Error())
		}
		base = home
	default:
		cwd, err := os.Getwd()
		if err != nil {
			return runtimeError(s, cmd.args, "skill", kindInternal, err.Error())
		}
		base = cwd
	}
	target := filepath.Join(base, ".agents", "skills", "snyk", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return runtimeError(s, cmd.args, "skill", kindInternal, err.Error())
	}
	action := "installed"
	if prev, err := os.ReadFile(target); err == nil && string(prev) == embedded.SkillMD {
		action = "already up to date"
	} else if err := writeFileAtomic(target, []byte(embedded.SkillMD), 0o644); err != nil {
		return runtimeError(s, cmd.args, "skill", kindInternal, err.Error())
	}
	summary := fmt.Sprintf("skill %s at %s", action, target)
	mode := output.ResolveMode(f.getBool("json"), false)
	return emit(s, mode, false, "skill", summary, map[string]any{"path": target}, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, summary)
		return err
	})
}

// writeFileAtomic writes data to a temp file inside the target directory,
// flushes it to disk and renames it into place, so an interrupted install
// can never leave a truncated SKILL.md behind — and a crash right after
// the rename cannot leave an empty one; the temp file is cleaned up on
// any failure.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	return os.Rename(name, path)
}
