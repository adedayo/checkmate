package model

// import (
// 	"context"

// 	pb "github.com/adedayo/checkmate-plugin/proto"
// )

// //CheckMatePluginServer is the gRPC server that the client talks to
// type CheckMatePluginServer struct {
// 	Impl CheckMatePluginInterface
// }

// //GetPluginMetadata returns the plugin metadata
// func (s *CheckMatePluginServer) GetPluginMetadata(
// 	ctx context.Context,
// 	req *pb.Empty) (*pb.PluginMetadata, error) {
// 	return s.Impl.GetPluginMetadata()
// }

// //Scan runs the static analysis scan against the plugin
// func (s *CheckMatePluginServer) Scan(req *pb.ScanRequest, server pb.PluginService_ScanServer) error {
// 	return s.Impl.Scan(req, server)
// }
