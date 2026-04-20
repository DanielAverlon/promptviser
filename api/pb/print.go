package pb

import (
	"fmt"
	"io"
	"strings"
	sync "sync"
	"time"

	"github.com/effective-security/protoc-gen-go/api"
	"github.com/effective-security/x/print"
	"github.com/effective-security/xdb"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

var (
	registerPrintOnce sync.Once
)

func RegisterPrintOnce() {
	// Register here all the custom functions that will be used to print the output of the CLI commands.
	registerPrintOnce.Do(func() {
		api.DefaultDescriber.RegisterEnumNameTypes(EnumNameTypes)

		//print.RegisterType(([]*SomeType)(nil), PrintLoginInfos)
	})
}

/*
func createTable(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithConfig(
			tablewriter.Config{
				Row: tw.CellConfig{
					Formatting: tw.CellFormatting{
						AutoWrap:  tw.WrapTruncate,
						Alignment: tw.AlignLeft,
					},
					ColMaxWidths: tw.CellWidth{Global: 64},
				},
			},
		))
}
*/

func createTableSimple(w io.Writer) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.BorderNone,
			//Symbols: tw.NewSymbols(tw.StyleASCII),
			Settings: tw.Settings{
				Separators: tw.Separators{BetweenRows: tw.Off},
				Lines:      tw.Lines{ShowFooterLine: tw.On, ShowHeaderLine: tw.On},
			},
		})),
		tablewriter.WithConfig(
			tablewriter.Config{
				Row: tw.CellConfig{
					Formatting: tw.CellFormatting{
						AutoWrap:  tw.WrapTruncate,
						Alignment: tw.AlignLeft,
					},
					ColMaxWidths: tw.CellWidth{Global: 128},
				},
			},
		))
}

func (r *ServerVersion) Print(w io.Writer) {
	fmt.Fprintf(w, "%s (%s)\n", r.Build, r.Runtime)
}

func (r *ServerStatusResponse) Print(w io.Writer) {
	table := createTableSimple(w)
	_ = table.Append([]string{"Name", r.Status.Name})
	_ = table.Append([]string{"Node", r.Status.Nodename})
	_ = table.Append([]string{"Host", r.Status.Hostname})
	_ = table.Append([]string{"Listen URLs", strings.Join(r.Status.ListenUrls, ",")})
	_ = table.Append([]string{"Version", r.Version.Build})
	_ = table.Append([]string{"Runtime", r.Version.Runtime})

	startedAt := xdb.ParseTime(r.Status.StartedAt).UTC()
	uptime := time.Since(startedAt) / time.Second * time.Second
	_ = table.Append([]string{"Started", startedAt.Format(time.RFC3339)})
	_ = table.Append([]string{"Uptime", uptime.String()})
	_ = table.Render()
	fmt.Fprintln(w)

	if len(r.Pods) > 0 {
		print.Map(w, []string{"Service", "Heartbeat"}, r.Pods)
	}
}
