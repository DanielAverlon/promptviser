package main

import (
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/cli/command"
	"github.com/effective-security/promptviser/api/version"
	"github.com/effective-security/x/ctl"
)

type app struct {
	cli.Cli

	Version command.VersionCmd `cmd:"" help:"print remote server version"`
	Server  command.ServerCmd  `cmd:"" help:"print remote server status"`
	//Caller     command.CallerCmd     `cmd:"" help:"print caller info"`

	Submit command.SubmitCmd `cmd:"" help:"Submit data for analysis"`
	Rules  command.RulesCmd  `cmd:"" help:"Print remote server rules"`
	Scan   command.ScanCmd   `cmd:"" help:"Scan prompts and return the findings"`
}

func main() {
	realMain(os.Args, os.Stdout, os.Stderr, os.Exit)
}

func realMain(args []string, out io.Writer, errout io.Writer, exit func(int)) {
	cl := app{
		Cli: cli.Cli{
			Version: ctl.VersionFlag("0.1.1"),
		},
	}
	cl.Cli.WithErrWriter(errout).
		WithWriter(out)

	parser, err := kong.New(&cl,
		kong.Name("promptviserctl"),
		kong.Description("CLI tool for promptviser service"),
		//kong.UsageOnError(),
		kong.Writers(out, errout),
		kong.Exit(exit),
		ctl.BoolPtrMapper,
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"version": version.Current().String(),
		})
	if err != nil {
		panic(err)
	}

	ctx, err := parser.Parse(args[1:])
	parser.FatalIfErrorf(err)

	if ctx != nil {
		err = ctx.Run(&cl.Cli)
		ctx.FatalIfErrorf(err)
	}
}
