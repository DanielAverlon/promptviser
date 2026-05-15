package command

import (
	"fmt"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/reporter"
)

type SubmitCmd struct {
	// TODO
	Data string `help:"Data to submit"`
}

func (cmd *SubmitCmd) Run(c *cli.Cli) error {
	adviser, err := c.AdviserClient(true)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to connect to adviser: %v\n", reporter.Warn, err)
		return err
	}

	data, err := c.Resolve(cmd.Data)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  failed to resolve data: %v\n", reporter.Warn, err)
		return err
	}

	fmt.Fprintf(c.ErrWriter(), "%s  submitting data...\n", reporter.Working)
	res, err := adviser.Submit(c.Context(), &pb.SubmitRequest{
		Data: data,
	})
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s  submit failed: %v\n", reporter.Warn, err)
		return err
	}

	return c.Print(res)
}
