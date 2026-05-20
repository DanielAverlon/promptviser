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
	scanID, err := saveScanResult(scanPath, resp)
	require.NoError(t, err)

	scansDir := filepath.Join(tempDir, ".config", "promptviser", "scans")
	files, err := os.ReadDir(scansDir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Check that the file name contains the scanID
	require.Contains(t, files[0].Name(), scanID)

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

	ts := time.Date(2026, 5, 9, 21, 46, 40, 0, time.UTC)
	slug := "home_daniel_fake-project"
	dummyID := "cafe1234"
	filename := fmt.Sprintf("%s_%s_%s.json", slug, dummyID, ts.UTC().Format("20060102T150405Z"))
	err = os.WriteFile(filepath.Join(scansDir, filename), []byte(`{}`), 0644)
	require.NoError(t, err)

	scans, err := listScans()
	require.NoError(t, err)
	require.Len(t, scans, 1)
	entries := scans["/home/daniel/fake-project"]
	require.NotNil(t, entries)
	require.Len(t, entries, 1)
	require.Equal(t, dummyID, entries[0].ID)
	require.WithinDuration(t, ts, entries[0].Timestamp, time.Second)
}

func Test_listScans(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	scansDir := filepath.Join(tempDir, ".config", "promptviser", "scans")
	err := os.MkdirAll(scansDir, 0755)
	require.NoError(t, err)

	// Create 3 scan files with new naming: slug_id_timestamp.json
	baseTime := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute)
		slug := fmt.Sprintf("home_daniel_fake-project-%d", i)
		id := fmt.Sprintf("deadbe%02d", i)
		filename := fmt.Sprintf("%s_%s_%s.json", slug, id, ts.UTC().Format("20060102T150405Z"))
		err = os.WriteFile(filepath.Join(scansDir, filename), []byte(`{}`), 0644)
		require.NoError(t, err)
	}

	scans, err := listScans()
	require.NoError(t, err)
	require.Len(t, scans, 3)
	for i := 1; i <= 3; i++ {
		project := fmt.Sprintf("/home/daniel/fake-project-%d", i)
		entries := scans[project]
		require.NotNil(t, entries)
		require.Equal(t, fmt.Sprintf("deadbe%02d", i), entries[0].ID)
	}
}

func Test_getScansDir(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	expected := filepath.Join(home, ".config", "promptviser", "scans")
	require.Equal(t, expected, getScansDir())
}
