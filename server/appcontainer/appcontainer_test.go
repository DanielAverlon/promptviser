package appcontainer

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/promptviser/api/client"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/x/guid"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const projFolder = "../../"

func TestNewContainerFactory(t *testing.T) {
	output := path.Join(os.TempDir(), "tests", "promptviser", guid.MustCreate())
	_ = os.MkdirAll(output, 0777)
	defer os.Remove(output)

	tcases := []struct {
		name string
		err  string
		cfg  *config.Configuration
	}{
		{
			name: "default",
			cfg:  &config.Configuration{},
		},
	}

	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			container, err := NewContainerFactory(nil).
				WithConfigurationProvider(func() (*config.Configuration, error) {
					return tc.cfg, nil
				}).
				CreateContainerWithDependencies()
			require.NoError(t, err)

			err = container.Invoke(func(cfg *config.Configuration,
				scheduler tasks.Scheduler,
			) {
			})
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			}
		})
	}
}

func TestAppContainer(t *testing.T) {
	t.Setenv("PROMPTVISER_JWT_SEED", "testseed")
	t.Setenv("PROMPTVISER_GITHUB_CLIENT_ID", "testclientid")
	t.Setenv("PROMPTVISER_GITHUB_CLIENT_SECRET", "testclientsecret")
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)

	f := NewContainerFactory(nil).
		WithConfigurationProvider(func() (*config.Configuration, error) {

			f, err := config.DefaultFactory()
			require.NoError(t, err)

			cfg := new(config.Configuration)
			_, err = f.LoadForHostName(cfgPath, "", cfg)
			require.NoError(t, err)

			return cfg, nil
		})

	container, err := f.CreateContainerWithDependencies()
	require.NoError(t, err)
	err = container.Invoke(func(
		_ *config.Configuration,
		_ tasks.Scheduler,
		_ adviserdb.Provider,
		_ jwt.Parser,
		_ client.Factory,
	) {
	})
	require.NoError(t, err)

}
