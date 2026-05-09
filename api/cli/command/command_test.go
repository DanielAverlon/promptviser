package command

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/promptviser/api/pb"
	"github.com/stretchr/testify/require"
)

func Test_SaveScan(t *testing.T) {
	// Set up a temporary directory to act as the scans output dir
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir) // redirect ~/.config/... to tempDir

	scanPath := "/home/daniel/fake-project"
	resp := &pb.MatchRulesResponse{
		Findings: []*pb.PromptFindings{
			{
				FileName: "test_prompt.txt",
				Findings: []*pb.Finding{},
			},
		},
	}
	err := saveScanResult(scanPath, resp)
	require.NoError(t, err)

	scansDir := filepath.Join(tempDir, ".config", "promptviser", "scans")
	files, err := os.ReadDir(scansDir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	content, err := os.ReadFile(filepath.Join(scansDir, files[0].Name()))
	require.NoError(t, err)
	require.Contains(t, string(content), "test_prompt.txt")
}

func Test_ListScan(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	scansDir := filepath.Join(tempDir, ".config", "promptviser", "scans")
	err := os.MkdirAll(scansDir, 0755)
	require.NoError(t, err)

	// Create a file using the real naming convention: <slug>_<timestamp>.json
	// slug for /home/daniel/fake-project → home_daniel_fake-project
	ts := time.Date(2026, 5, 9, 21, 46, 40, 0, time.UTC)
	filename := fmt.Sprintf("home_daniel_fake-project_%s.json", ts.UTC().Format("20060102T150405Z"))
	err = os.WriteFile(filepath.Join(scansDir, filename), []byte(`{}`), 0644)
	require.NoError(t, err)

	scans, err := listScans()
	require.NoError(t, err)
	require.Len(t, scans, 1)
	require.Equal(t, "/home/daniel/fake-project", scans[0].ProjectPath)
	require.WithinDuration(t, ts, scans[0].Timestamp, time.Second)
}

func Test_listScans(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	scansDir := filepath.Join(tempDir, ".config", "promptviser", "scans")
	err := os.MkdirAll(scansDir, 0755)
	require.NoError(t, err)

	// Create 3 scan files with proper naming: slug_timestamp.json
	baseTime := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute)
		filename := fmt.Sprintf("home_daniel_fake-project-%d_%s.json", i, ts.UTC().Format("20060102T150405Z"))
		err = os.WriteFile(filepath.Join(scansDir, filename), []byte(`{}`), 0644)
		require.NoError(t, err)
	}

	scans, err := listScans()
	require.NoError(t, err)
	require.Len(t, scans, 3)
	for i, scan := range scans {
		require.Equal(t, fmt.Sprintf("/home/daniel/fake-project-%d", i+1), scan.ProjectPath)
	}
}

func Test_getScansDir(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	expected := filepath.Join(home, ".config", "promptviser", "scans")
	require.Equal(t, expected, getScansDir())
}
