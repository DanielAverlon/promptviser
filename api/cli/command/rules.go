package command

import (
	"fmt"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/reporter"
)

// RulesCmd prints remote server rules
type RulesCmd struct {
	Verbose bool `short:"v" help:"Verbose output"`
}

func (cmd *RulesCmd) Run(c *cli.Cli) error {
	fmt.Fprintf(c.ErrWriter(), "%s  fetching rules...\n", reporter.Working)
	adviser, err := c.AdviserClient(true)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to connect to adviser: %v\n", reporter.Warn, err)
		return err
	}

	res, err := adviser.GetRules(c.Context(), &pb.GetRulesRequest{})
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to fetch rules: %v\n", reporter.Warn, err)
		return err
	}
	fmt.Fprintf(c.ErrWriter(), "%s  %d rule(s) loaded\n", reporter.Info, len(res.Rules))

	if cmd.Verbose || !reporter.IsTerminal() {
		return c.Print(res)
	}

	reporter.PrintRulesList(res)
	return nil
}
