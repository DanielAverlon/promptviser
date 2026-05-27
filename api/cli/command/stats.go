package command

import (
	"fmt"

	"github.com/effective-security/promptviser/api/cli"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/internal/reporter"
)

// StatsCmd fetches aggregated rule-violation statistics from the server.
type StatsCmd struct {
	Limit int `short:"n" help:"Maximum number of top violations to show" default:"10"`
}

// Run the command
func (a *StatsCmd) Run(c *cli.Cli) error {
	// GetStatsRequest/Response are plain Go structs (not proto.Message) so they
	// cannot be marshalled by the gRPC binary codec. Force the HTTP/JSON path.
	origHTTP := c.HTTP
	c.HTTP = true
	defer func() { c.HTTP = origHTTP }()

	adviser, err := c.AdviserClient(true)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\tfailed to connect to adviser: %v\n", reporter.Warn, err)
		return fmt.Errorf("failed to connect to adviser: %w", err)
	}

	req := &pb.GetStatsRequest{Limit: int32(a.Limit)}
	resp, err := adviser.GetStats(c.Context(), req)
	if err != nil {
		fmt.Fprintf(c.ErrWriter(), "%s\tGetStats failed: %v\n", reporter.Warn, err)
		return fmt.Errorf("GetStats: %w", err)
	}

	if c.O != "" {
		return c.Print(resp)
	}

	reporter.PrintStats(resp)
	return nil
}
