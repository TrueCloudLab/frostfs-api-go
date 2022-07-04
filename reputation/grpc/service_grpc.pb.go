// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.4
// source: reputation/grpc/service.proto

package reputation

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ReputationServiceClient is the client API for ReputationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ReputationServiceClient interface {
	// Announce local client trust information to any node in NeoFS network.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS):
	// local trust has been successfully announced;
	// - Common failures (SECTION_FAILURE_COMMON).
	AnnounceLocalTrust(ctx context.Context, in *AnnounceLocalTrustRequest, opts ...grpc.CallOption) (*AnnounceLocalTrustResponse, error)
	// Announce the intermediate result of the iterative algorithm for
	// calculating the global reputation of the node in NeoFS network.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS):
	// intermediate trust estimation has been successfully announced;
	// - Common failures (SECTION_FAILURE_COMMON).
	AnnounceIntermediateResult(ctx context.Context, in *AnnounceIntermediateResultRequest, opts ...grpc.CallOption) (*AnnounceIntermediateResultResponse, error)
}

type reputationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewReputationServiceClient(cc grpc.ClientConnInterface) ReputationServiceClient {
	return &reputationServiceClient{cc}
}

func (c *reputationServiceClient) AnnounceLocalTrust(ctx context.Context, in *AnnounceLocalTrustRequest, opts ...grpc.CallOption) (*AnnounceLocalTrustResponse, error) {
	out := new(AnnounceLocalTrustResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.reputation.ReputationService/AnnounceLocalTrust", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *reputationServiceClient) AnnounceIntermediateResult(ctx context.Context, in *AnnounceIntermediateResultRequest, opts ...grpc.CallOption) (*AnnounceIntermediateResultResponse, error) {
	out := new(AnnounceIntermediateResultResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.reputation.ReputationService/AnnounceIntermediateResult", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReputationServiceServer is the server API for ReputationService service.
// All implementations should embed UnimplementedReputationServiceServer
// for forward compatibility
type ReputationServiceServer interface {
	// Announce local client trust information to any node in NeoFS network.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS):
	// local trust has been successfully announced;
	// - Common failures (SECTION_FAILURE_COMMON).
	AnnounceLocalTrust(context.Context, *AnnounceLocalTrustRequest) (*AnnounceLocalTrustResponse, error)
	// Announce the intermediate result of the iterative algorithm for
	// calculating the global reputation of the node in NeoFS network.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS):
	// intermediate trust estimation has been successfully announced;
	// - Common failures (SECTION_FAILURE_COMMON).
	AnnounceIntermediateResult(context.Context, *AnnounceIntermediateResultRequest) (*AnnounceIntermediateResultResponse, error)
}

// UnimplementedReputationServiceServer should be embedded to have forward compatible implementations.
type UnimplementedReputationServiceServer struct {
}

func (UnimplementedReputationServiceServer) AnnounceLocalTrust(context.Context, *AnnounceLocalTrustRequest) (*AnnounceLocalTrustResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AnnounceLocalTrust not implemented")
}
func (UnimplementedReputationServiceServer) AnnounceIntermediateResult(context.Context, *AnnounceIntermediateResultRequest) (*AnnounceIntermediateResultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AnnounceIntermediateResult not implemented")
}

// UnsafeReputationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ReputationServiceServer will
// result in compilation errors.
type UnsafeReputationServiceServer interface {
	mustEmbedUnimplementedReputationServiceServer()
}

func RegisterReputationServiceServer(s grpc.ServiceRegistrar, srv ReputationServiceServer) {
	s.RegisterService(&ReputationService_ServiceDesc, srv)
}

func _ReputationService_AnnounceLocalTrust_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AnnounceLocalTrustRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ReputationServiceServer).AnnounceLocalTrust(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.reputation.ReputationService/AnnounceLocalTrust",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ReputationServiceServer).AnnounceLocalTrust(ctx, req.(*AnnounceLocalTrustRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ReputationService_AnnounceIntermediateResult_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AnnounceIntermediateResultRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ReputationServiceServer).AnnounceIntermediateResult(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.reputation.ReputationService/AnnounceIntermediateResult",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ReputationServiceServer).AnnounceIntermediateResult(ctx, req.(*AnnounceIntermediateResultRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ReputationService_ServiceDesc is the grpc.ServiceDesc for ReputationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ReputationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "neo.fs.v2.reputation.ReputationService",
	HandlerType: (*ReputationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AnnounceLocalTrust",
			Handler:    _ReputationService_AnnounceLocalTrust_Handler,
		},
		{
			MethodName: "AnnounceIntermediateResult",
			Handler:    _ReputationService_AnnounceIntermediateResult_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "reputation/grpc/service.proto",
}
