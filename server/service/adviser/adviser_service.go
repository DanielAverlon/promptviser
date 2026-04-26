package adviser

import (
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/restserver"
	"github.com/effective-security/promptviser/api/pb"
	"github.com/effective-security/promptviser/api/pb/httppb"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/xlog"
	"google.golang.org/grpc"
)

// ServiceName provides the Service Name for this package
const ServiceName = "adviser"

var logger = xlog.NewPackageLogger("github.com/effective-security/promptviser/server/service", "adviser")

// Service defines the Adviser service
type Service struct {
	server gserver.GServer
	db     adviserdb.AdviserDb
}

// Factory returns a factory of the service.
// The returned func is called by the dig container, which injects the DB.
func Factory(server gserver.GServer) any {
	if server == nil {
		logger.Panic("adviser.Factory: invalid parameter")
	}

	return func(db adviserdb.Provider) {
		svc := &Service{
			server: server,
			db:     db,
		}

		server.AddService(svc)
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return ServiceName
}

// NewServiceForTest creates a Service wired to the given DB without requiring a
// live gRPC server or the dig container. Intended for unit tests only.
func NewServiceForTest(db adviserdb.AdviserDb) *Service {
	return &Service{db: db}
}

// IsReady indicates that the service is ready to serve its end-points
func (s *Service) IsReady() bool {
	return true
}

// Close the subservices and it's resources
func (s *Service) Close() {
	logger.KV(xlog.INFO, "closed", ServiceName)
}

func (s *Service) AdviserHTTPHandler() restserver.Handle {
	return httppb.GetAdviserHTTPHandler(s, nil)
}

// RegisterRoute adds the Status API endpoints to the overall URL router
func (s *Service) RegisterRoute(r restserver.Router) {
	r.POST("/pb.Adviser/:action", s.AdviserHTTPHandler())
}

// RegisterGRPC registers gRPC handler
func (s *Service) RegisterGRPC(r *grpc.Server) {
	pb.RegisterAdviserServer(r, s)
}
