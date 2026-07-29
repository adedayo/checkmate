package model

// import (
// 	"context"

// 	pb "github.com/adedayo/checkmate-plugin/proto"
// )

// // CheckMatePluginClient client
// type CheckMatePluginClient struct {
// 	client pb.PluginServiceClient
// }

// //GetPluginMetadata returns the plugin metadata
// func (c *CheckMatePluginClient) GetPluginMetadata() (*pb.PluginMetadata, error) {

// 	return c.client.GetPluginMetadata(context.Background(), &pb.Empty{})
// }

// // Scan sends a scan request for processing to the server
// func (c *CheckMatePluginClient) Scan(req *pb.ScanRequest) (pb.PluginService_ScanClient, error) {
// 	client, err := c.client.Scan(context.Background(), req)
// 	return client, err
// }
