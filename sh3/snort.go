package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"rsc.io/script"
)

var snort_path = "/bin/snort"
var daq_path = "/lib"

// snort runs snort against PCAP files.
// A default configuration, optionally in multiple files, is attached from the txtar by the runner.
func snort(gdb bool) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "run snort against pcap files",
			Args:    "files...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var expect_fail bool

			fs := flag.NewFlagSet("pcap", flag.ContinueOnError)
			fs.BoolVar(&expect_fail, "expect-fail", false, "expect failure")
			if err := fs.Parse(args); err != nil {
				return nil, err
			}
			file_list := fs.Args()
			if len(file_list) < 1 {
				return nil, script.ErrUsage
			}

			var stdoutBuf, stderrBuf strings.Builder

			cargs := []string{"-c", s.Path("cfg.lua"),
				"--plugin-path", s.Path("p"),
				"--warn-all",
				"--pcap-list", strings.Join(file_list, " ")}
			var cmd *exec.Cmd
			if gdb {
				cmd = exec.CommandContext(s.Context(), "gdb", append([]string{"--args", s.Path("bin/snort")}, cargs...)...)
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
			} else {
				cmd = exec.CommandContext(s.Context(), s.Path("bin/snort"), cargs...)
				cmd.Stdout = &stdoutBuf
				cmd.Stderr = &stderrBuf
			}

			cmd.Dir = s.Getwd()
			cmd.Env = s.Environ()

			err := cmd.Start()
			if err != nil {
				return nil, err
			}

			wait := func(s *script.State) (stdout, stderr string, err error) {
				err = cmd.Wait()

				if expect_fail && err != nil {
					err = nil
				} else if expect_fail {
					err = fmt.Errorf("Expected error, but it didn't happen")
				}

				return stdoutBuf.String(), stderrBuf.String(), err
			}
			return wait, nil
		},
	)
}

func Skip() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "skip the current test",
			Args:    "[msg]",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) > 1 {
				return nil, script.ErrUsage
			}
			if len(args) == 0 {
				return nil, skipError{""}
			}
			return nil, skipError{args[0]}
		})
}

type skipError struct{ msg string }

func (err skipError) Error() string { return err.msg }

func Eq() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "check if two files are byte-equal",
			Args:    "f1 f2",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, script.ErrUsage
			}

			f1, err := os.ReadFile(s.Path(args[0]))
			if err != nil {
				return nil, fmt.Errorf("opening %s: %w", args[0], err)
			}

			f2, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("opening %s: %w", args[1], err)
			}

			if !bytes.Equal(f1, f2) {
				return nil, fmt.Errorf("file %s and %s differ", args[0], args[1])
			}

			return nil, nil
		})
}
