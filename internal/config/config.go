package config

import (
	"github.com/effective-security/porto/gserver"
	appinit "github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/promptviser/api/client"
	"github.com/effective-security/xlog"
)

const (
	// WFEServerName specifies server name for Web Front End
	WFEServerName = "wfe"
)

// Configuration contains the user configurable data for the service
type Configuration struct {

	// Region specifies the Region / Datacenter where the instance is running
	Region string `json:"region,omitempty" yaml:"region,omitempty"`

	// Environment specifies the environment where the instance is running: prod|stage|dev
	Environment string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// ServiceName specifies the service name to be used in logs, metrics, etc
	ServiceName string `json:"service,omitempty" yaml:"service,omitempty"`

	// ClusterName specifies the cluster name
	ClusterName string `json:"cluster,omitempty" yaml:"cluster,omitempty"`

	// Metrics specifies the metrics pipeline configuration
	Metrics appinit.Metrics `json:"metrics" yaml:"metrics"`

	// LogLevels specifies the log levels per package
	LogLevels []xlog.RepoLogLevel `json:"log_levels" yaml:"log_levels"`

	// SQL specifies the configuration for SQL provider
	SQL SQL `json:"sql" yaml:"sql"`

	// JWT specifies configuration file for the JWT provider
	JWT string `json:"jwt_provider" yaml:"jwt_provider"`

	// OAuth2Clients specifies configuration file for the OAuth2 Clients provider
	OAuth2Clients string `json:"oauth2_clients" yaml:"oauth2_clients"`

	// HTTPServers specifies a list of servers that expose HTTP or gRPC services
	HTTPServers map[string]*gserver.Config `json:"servers" yaml:"servers"`

	// Client specifies configurations for the client to connect to the cluster
	Client client.Config `json:"client" yaml:"client"`

	// Tasks specifies array of tasks
	Tasks []Task `json:"tasks" yaml:"tasks"`
}

// Task specifies configuration of a single task.
type Task struct {

	// Name specifies the name of the task.
	Name string `json:"name" yaml:"name"`

	// Schedule specifies the schedule of this task.
	Schedule string `json:"schedule" yaml:"schedule"`

	// Args specifies parameters for the task.
	Args []string `json:"args" yaml:"args"`
}
