package main

import (
	"fmt"
	"os/exec"
	"strings"

	"rsc.io/script"
)

var snortloc = "/opt/snort/bin/snort"

// var snortloc = "/home/mike/code/snort/snort3/build/src/snort"
var luascript = "/opt/snort/include/snort/lua/?.lua;;"

var asanlib string

// PCAP runs snort against PCAP files, without any rule.
// $(SNORT) -v -c cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all
func PCAP(opts ...CompileOpt) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "run snort against pcap files",
			Args:    "[-expect-fail] files...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var file_list []string
			expect_fail := false
			for i, arg := range args {
				if arg[0] == '-' {
					switch arg[1:] {
					case "expect-fail":
						expect_fail = true
					default:
						return nil, fmt.Errorf("Invalid parameter '%s' to PCAP", arg)
					}
				} else {
					file_list = args[i:]
					break
				}
			}

			if len(file_list) < 1 {
				return nil, script.ErrUsage
			}

			var stdoutBuf, stderrBuf strings.Builder

			cmd := exec.CommandContext(s.Context(), snortloc,
				"-c", s.Path("cfg.lua"),
				"--script-path", ".",
				"--plugin-path", "p",
				"--pcap-list", strings.Join(file_list, " "),
				"--warn-all",
			)
			cmd.Dir = s.Getwd()
			// TODO only preload if asan is set
			cmd.Env = append(s.Environ(), "LUA_PATH="+luascript)
			for _, o := range opts {
				cmd.Args, cmd.Env = o(cmd.Args, cmd.Env)
			}

			cmd.Stdout = &stdoutBuf
			cmd.Stderr = &stderrBuf

			err := cmd.Start()
			if err != nil {
				return nil, err
			}

			wait := func(s *script.State) (stdout, stderr string, err error) {
				err = cmd.Wait()

				if expect_fail {
					if err != nil {
						err = nil
					} else {
						err = fmt.Errorf("Expected error, but it didn't happen")
					}
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
