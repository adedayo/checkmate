package model

// import (
// 	"context"

// 	pb "github.com/adedayo/checkmate-plugin/proto"
// 	"github.com/hashicorp/go-plugin"

// 	"google.golang.org/grpc"
// )

// var (
// 	//MagicCookie is a global plugin cookie to be used by all CheckMate plugins
// 	MagicCookie = "CheckMate_Plugin_Cookie"
// 	//MagicCookieValue is a global plugin cookie to be used by all CheckMate plugins
// 	MagicCookieValue = "7ac3958e-8bbc-11ea-9455-5bcc09dc1c7d"
// )

// // CheckMatePluginInterface is the interface that all plugins must implement
// type CheckMatePluginInterface interface {
// 	//GetPluginMetadata returns meta data description of the plugin
// 	GetPluginMetadata() (*pb.PluginMetadata, error)
// 	Scan(*pb.ScanRequest, pb.PluginService_ScanServer) error
// }

// // CheckMatePluginClientInterface is the interface that plugin clients implement
// type CheckMatePluginClientInterface interface {
// 	//GetPluginMetadata returns meta data description of the plugin
// 	GetPluginMetadata() (*pb.PluginMetadata, error)
// 	Scan(*pb.ScanRequest) error
// }

// // PluginMetadata a
// type PluginMetadata struct {
// 	//Plugin ID used to serve the plugin
// 	ID string
// 	//Name of the plugin, for user inter
// 	Name string
// 	//A display description
// 	Description string
// 	//A filesystem path from where the plugin should be launched from
// 	Path string
// }

// // CheckMatePluginContainer is plugin.Plugin implementation
// type CheckMatePluginContainer struct {
// 	plugin.Plugin
// 	Impl CheckMatePluginInterface
// }

// // GRPCServer registers this plugin for serving with the
// // given GRPCServer. Unlike Plugin.Server, this is only called once
// // since gRPC plugins serve singletons.
// func (p *CheckMatePluginContainer) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
// 	pb.RegisterPluginServiceServer(s, &CheckMatePluginServer{Impl: p.Impl})
// 	return nil
// }

// // GRPCClient returns the interface implementation for the plugin
// // you're serving via gRPC. The provided context will be canceled by
// // go-plugin in the event of the plugin process exiting.
// func (p *CheckMatePluginContainer) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
// 	return &CheckMatePluginClient{client: pb.NewPluginServiceClient(c)}, nil
// }
