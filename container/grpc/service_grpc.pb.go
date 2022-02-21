// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.4
// source: container/grpc/service.proto

package container

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

// ContainerServiceClient is the client API for ContainerService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ContainerServiceClient interface {
	// `Put` invokes `Container` smart contract's `Put` method and returns
	// response immediately. After a new block is issued in sidechain, request is
	// verified by Inner Ring nodes. After one more block in sidechain, container
	// is added into smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   request to save the container has been sent to the sidechain;
	// - Common failures (SECTION_FAILURE_COMMON).
	Put(ctx context.Context, in *PutRequest, opts ...grpc.CallOption) (*PutResponse, error)
	// `Delete` invokes `Container` smart contract's `Delete` method and returns
	// response immediately. After a new block is issued in sidechain, request is
	// verified by Inner Ring nodes. After one more block in sidechain, container
	// is added into smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   request to remove the container has been sent to the sidechain;
	// - Common failures (SECTION_FAILURE_COMMON).
	Delete(ctx context.Context, in *DeleteRequest, opts ...grpc.CallOption) (*DeleteResponse, error)
	// Returns container structure from `Container` smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   container has been successfully read;
	// - Common failures (SECTION_FAILURE_COMMON);
	// - **CONTAINER_NOT_FOUND** (3072, SECTION_CONTAINER): \
	//   requested container not found.
	Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error)
	// Returns all owner's containers from 'Container` smart contract' storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   container list has been successfully read;
	// - Common failures (SECTION_FAILURE_COMMON).
	List(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error)
	// Invokes 'SetEACL' method of 'Container` smart contract and returns response
	// immediately. After one more block in sidechain, Extended ACL changes are
	// added into smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   request to save container eACL has been sent to the sidechain;
	// - Common failures (SECTION_FAILURE_COMMON).
	SetExtendedACL(ctx context.Context, in *SetExtendedACLRequest, opts ...grpc.CallOption) (*SetExtendedACLResponse, error)
	// Returns Extended ACL table and signature from `Container` smart contract
	// storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   container eACL has been successfully read;
	// - Common failures (SECTION_FAILURE_COMMON);
	// - **CONTAINER_NOT_FOUND** (3072, SECTION_CONTAINER): \
	//   container not found.
	GetExtendedACL(ctx context.Context, in *GetExtendedACLRequest, opts ...grpc.CallOption) (*GetExtendedACLResponse, error)
	// Announce container used space values for P2P synchronization.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   estimation of used space has been successfully announced;
	// - Common failures (SECTION_FAILURE_COMMON).
	AnnounceUsedSpace(ctx context.Context, in *AnnounceUsedSpaceRequest, opts ...grpc.CallOption) (*AnnounceUsedSpaceResponse, error)
}

type containerServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewContainerServiceClient(cc grpc.ClientConnInterface) ContainerServiceClient {
	return &containerServiceClient{cc}
}

func (c *containerServiceClient) Put(ctx context.Context, in *PutRequest, opts ...grpc.CallOption) (*PutResponse, error) {
	out := new(PutResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/Put", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *containerServiceClient) Delete(ctx context.Context, in *DeleteRequest, opts ...grpc.CallOption) (*DeleteResponse, error) {
	out := new(DeleteResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *containerServiceClient) Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error) {
	out := new(GetResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *containerServiceClient) List(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error) {
	out := new(ListResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *containerServiceClient) SetExtendedACL(ctx context.Context, in *SetExtendedACLRequest, opts ...grpc.CallOption) (*SetExtendedACLResponse, error) {
	out := new(SetExtendedACLResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/SetExtendedACL", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *containerServiceClient) GetExtendedACL(ctx context.Context, in *GetExtendedACLRequest, opts ...grpc.CallOption) (*GetExtendedACLResponse, error) {
	out := new(GetExtendedACLResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/GetExtendedACL", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *containerServiceClient) AnnounceUsedSpace(ctx context.Context, in *AnnounceUsedSpaceRequest, opts ...grpc.CallOption) (*AnnounceUsedSpaceResponse, error) {
	out := new(AnnounceUsedSpaceResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.container.ContainerService/AnnounceUsedSpace", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ContainerServiceServer is the server API for ContainerService service.
// All implementations should embed UnimplementedContainerServiceServer
// for forward compatibility
type ContainerServiceServer interface {
	// `Put` invokes `Container` smart contract's `Put` method and returns
	// response immediately. After a new block is issued in sidechain, request is
	// verified by Inner Ring nodes. After one more block in sidechain, container
	// is added into smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   request to save the container has been sent to the sidechain;
	// - Common failures (SECTION_FAILURE_COMMON).
	Put(context.Context, *PutRequest) (*PutResponse, error)
	// `Delete` invokes `Container` smart contract's `Delete` method and returns
	// response immediately. After a new block is issued in sidechain, request is
	// verified by Inner Ring nodes. After one more block in sidechain, container
	// is added into smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   request to remove the container has been sent to the sidechain;
	// - Common failures (SECTION_FAILURE_COMMON).
	Delete(context.Context, *DeleteRequest) (*DeleteResponse, error)
	// Returns container structure from `Container` smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   container has been successfully read;
	// - Common failures (SECTION_FAILURE_COMMON);
	// - **CONTAINER_NOT_FOUND** (3072, SECTION_CONTAINER): \
	//   requested container not found.
	Get(context.Context, *GetRequest) (*GetResponse, error)
	// Returns all owner's containers from 'Container` smart contract' storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   container list has been successfully read;
	// - Common failures (SECTION_FAILURE_COMMON).
	List(context.Context, *ListRequest) (*ListResponse, error)
	// Invokes 'SetEACL' method of 'Container` smart contract and returns response
	// immediately. After one more block in sidechain, Extended ACL changes are
	// added into smart contract storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   request to save container eACL has been sent to the sidechain;
	// - Common failures (SECTION_FAILURE_COMMON).
	SetExtendedACL(context.Context, *SetExtendedACLRequest) (*SetExtendedACLResponse, error)
	// Returns Extended ACL table and signature from `Container` smart contract
	// storage.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   container eACL has been successfully read;
	// - Common failures (SECTION_FAILURE_COMMON);
	// - **CONTAINER_NOT_FOUND** (3072, SECTION_CONTAINER): \
	//   container not found.
	GetExtendedACL(context.Context, *GetExtendedACLRequest) (*GetExtendedACLResponse, error)
	// Announce container used space values for P2P synchronization.
	//
	// Statuses:
	// - **OK** (0, SECTION_SUCCESS): \
	//   estimation of used space has been successfully announced;
	// - Common failures (SECTION_FAILURE_COMMON).
	AnnounceUsedSpace(context.Context, *AnnounceUsedSpaceRequest) (*AnnounceUsedSpaceResponse, error)
}

// UnimplementedContainerServiceServer should be embedded to have forward compatible implementations.
type UnimplementedContainerServiceServer struct {
}

func (UnimplementedContainerServiceServer) Put(context.Context, *PutRequest) (*PutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Put not implemented")
}
func (UnimplementedContainerServiceServer) Delete(context.Context, *DeleteRequest) (*DeleteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedContainerServiceServer) Get(context.Context, *GetRequest) (*GetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedContainerServiceServer) List(context.Context, *ListRequest) (*ListResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedContainerServiceServer) SetExtendedACL(context.Context, *SetExtendedACLRequest) (*SetExtendedACLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetExtendedACL not implemented")
}
func (UnimplementedContainerServiceServer) GetExtendedACL(context.Context, *GetExtendedACLRequest) (*GetExtendedACLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetExtendedACL not implemented")
}
func (UnimplementedContainerServiceServer) AnnounceUsedSpace(context.Context, *AnnounceUsedSpaceRequest) (*AnnounceUsedSpaceResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AnnounceUsedSpace not implemented")
}

// UnsafeContainerServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ContainerServiceServer will
// result in compilation errors.
type UnsafeContainerServiceServer interface {
	mustEmbedUnimplementedContainerServiceServer()
}

func RegisterContainerServiceServer(s grpc.ServiceRegistrar, srv ContainerServiceServer) {
	s.RegisterService(&ContainerService_ServiceDesc, srv)
}

func _ContainerService_Put_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PutRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).Put(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/Put",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).Put(ctx, req.(*PutRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContainerService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).Delete(ctx, req.(*DeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContainerService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).Get(ctx, req.(*GetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContainerService_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).List(ctx, req.(*ListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContainerService_SetExtendedACL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetExtendedACLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).SetExtendedACL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/SetExtendedACL",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).SetExtendedACL(ctx, req.(*SetExtendedACLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContainerService_GetExtendedACL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetExtendedACLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).GetExtendedACL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/GetExtendedACL",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).GetExtendedACL(ctx, req.(*GetExtendedACLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContainerService_AnnounceUsedSpace_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AnnounceUsedSpaceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContainerServiceServer).AnnounceUsedSpace(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.container.ContainerService/AnnounceUsedSpace",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContainerServiceServer).AnnounceUsedSpace(ctx, req.(*AnnounceUsedSpaceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ContainerService_ServiceDesc is the grpc.ServiceDesc for ContainerService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ContainerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "neo.fs.v2.container.ContainerService",
	HandlerType: (*ContainerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Put",
			Handler:    _ContainerService_Put_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _ContainerService_Delete_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _ContainerService_Get_Handler,
		},
		{
			MethodName: "List",
			Handler:    _ContainerService_List_Handler,
		},
		{
			MethodName: "SetExtendedACL",
			Handler:    _ContainerService_SetExtendedACL_Handler,
		},
		{
			MethodName: "GetExtendedACL",
			Handler:    _ContainerService_GetExtendedACL_Handler,
		},
		{
			MethodName: "AnnounceUsedSpace",
			Handler:    _ContainerService_AnnounceUsedSpace_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "container/grpc/service.proto",
}
