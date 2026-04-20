package appcontainer

import (
	"io"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/promptviser/api/client"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/xdb/pkg/flake"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
	"go.uber.org/dig"

	// register providers
	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	_ "github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/promptviser/internal", "appcontainer")

// ContainerFactoryFn defines an app container factory interface
type ContainerFactoryFn func() (*dig.Container, error)

// ProvideConfigurationFn defines Configuration provider
type ProvideConfigurationFn func() (*config.Configuration, error)

// ProvideDiscoveryFn defines Discovery provider
type ProvideDiscoveryFn func() (discovery.Discovery, error)

// ProvideSchedulerFn defines Scheduler provider
type ProvideSchedulerFn func() (tasks.Scheduler, error)

// ProvideJwtFn defines JWT provider
type ProvideJwtFn func(cfg *config.Configuration, dp dataprotection.Provider) (jwt.Parser, jwt.Signer, error)

// ProvideCaDbFn defines CA DB provider
type ProvideAdviserDbFn func(cfg *config.Configuration) (adviserdb.Provider, error)

// ProvideClientFactoryFn defines client.Facroty provider
type ProvideClientFactoryFn func(cfg *config.Configuration) (client.Factory, error)

// ProvideDataprotectionFn defines data protection provider
type ProvideDataprotectionFn func() (dataprotection.Provider, error)

// CloseRegistrator provides interface to release resources on close
type CloseRegistrator interface {
	OnClose(closer io.Closer)
}

// ContainerFactory is default implementation
type ContainerFactory struct {
	closer CloseRegistrator

	configProvider        ProvideConfigurationFn
	discoveryProvider     ProvideDiscoveryFn
	schedulerProvider     ProvideSchedulerFn
	adviserDbProvider     ProvideAdviserDbFn
	jwtProvider           ProvideJwtFn
	clientFactoryProvider ProvideClientFactoryFn
	dpProvider            ProvideDataprotectionFn
}

// NewContainerFactory returns an instance of ContainerFactory
func NewContainerFactory(closer CloseRegistrator) *ContainerFactory {
	f := &ContainerFactory{
		closer: closer,
	}

	defaultSchedulerProv := func() (tasks.Scheduler, error) {
		return tasks.NewScheduler(), nil
	}

	// configure with default providers
	return f.
		WithDiscoveryProvider(provideDiscovery).
		WithSchedulerProvider(defaultSchedulerProv).
		WithJwtProvider(provideJwt).
		WithAdviserDbProvider(provideAdviserDb).
		WithClientFactoryProvider(provideClientFactory).
		WithDataprotectionProvider(provideDp)
}

// WithConfigurationProvider allows to specify configuration
func (f *ContainerFactory) WithConfigurationProvider(p ProvideConfigurationFn) *ContainerFactory {
	f.configProvider = p
	return f
}

// WithDiscoveryProvider allows to specify Discovery
func (f *ContainerFactory) WithDiscoveryProvider(p ProvideDiscoveryFn) *ContainerFactory {
	f.discoveryProvider = p
	return f
}

// WithDataprotectionProvider allows to specify Data protection provider
func (f *ContainerFactory) WithDataprotectionProvider(p ProvideDataprotectionFn) *ContainerFactory {
	f.dpProvider = p
	return f
}

// WithClientFactoryProvider allows to specify custom client.Factory provider
func (f *ContainerFactory) WithClientFactoryProvider(p ProvideClientFactoryFn) *ContainerFactory {
	f.clientFactoryProvider = p
	return f
}

// WithJwtProvider allows to specify custom JWT provider
func (f *ContainerFactory) WithJwtProvider(p ProvideJwtFn) *ContainerFactory {
	f.jwtProvider = p
	return f
}

// WithAdviserDbProvider allows to specify custom DB provider
func (f *ContainerFactory) WithAdviserDbProvider(p ProvideAdviserDbFn) *ContainerFactory {
	f.adviserDbProvider = p
	return f
}

// WithSchedulerProvider allows to specify custom Scheduler
func (f *ContainerFactory) WithSchedulerProvider(p ProvideSchedulerFn) *ContainerFactory {
	f.schedulerProvider = p
	return f
}

// CreateContainerWithDependencies returns an instance of Container
func (f *ContainerFactory) CreateContainerWithDependencies() (*dig.Container, error) {
	container := dig.New()

	constructors := []any{
		f.configProvider,
		func() CloseRegistrator {
			return f.closer
		},
		f.discoveryProvider,
		f.schedulerProvider,
		f.jwtProvider,
		f.adviserDbProvider,
		f.clientFactoryProvider,
		f.dpProvider,
	}

	for idx, c := range constructors {
		err := container.Provide(c)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to provide constructor %d: %T", idx, c)
		}
	}

	return container, nil
}

func provideDiscovery() (discovery.Discovery, error) {
	return discovery.New(), nil
}

func provideJwt(cfg *config.Configuration, dp dataprotection.Provider) (jwt.Parser, jwt.Signer, error) {
	var provider jwt.Provider
	var err error
	if cfg.JWT != "" {
		provider, err = jwt.LoadProvider(cfg.JWT, nil)
		if err != nil {
			return nil, nil, err
		}
	}
	// we encrypt Admin access token,
	// the accesstoken provider handles both, encrypted PAT and plain JWT
	at := accesstoken.New(dp, provider)
	return at, at, nil
}

func provideAdviserDb(cfg *config.Configuration) (adviserdb.Provider, error) {
	d, err := adviserdb.New(
		cfg.SQL.DataSource,
		cfg.SQL.MigrationsDir,
		cfg.SQL.ForceVersion,
		cfg.SQL.MigrateVersion,
		flake.DefaultIDGenerator)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func provideClientFactory(cfg *config.Configuration) (client.Factory, error) {
	var ops []client.Option
	// if cfg.Client.EnableCNA {
	// 	ci := awsprov.NewCallerIdentity(awsFactory, 5*time.Minute, nil)
	// 	ops = append(ops, client.WithCallerIdentity(ci))
	// }
	return client.NewFactory(cfg.Client, ops...), nil
}

func provideDp() (dataprotection.Provider, error) {
	seed := os.Getenv("PROMPTVISER_JWT_SEED")
	if seed == "" {
		return nil, errors.Errorf("PROMPTVISER_JWT_SEED not defined")
	}
	p, err := dataprotection.NewSymmetric([]byte(seed))
	if err != nil {
		return nil, err
	}
	return p, nil
}
