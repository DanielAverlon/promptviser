package command

import (
	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
)

// RulesCmd prints remote server rules
type RulesCmd struct {
}

func (cmd *RulesCmd) Run(c *cli.Cli) error {
	adviser, err := c.AdviserClient(true)
	if err != nil {
		return err
	}

	res, err := adviser.GetRules(c.Context(), &pb.GetRulesRequest{})
	if err != nil {
		return err
	}

	return c.Print(res)
}
