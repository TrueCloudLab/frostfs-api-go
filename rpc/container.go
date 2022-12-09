package rpc

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/container"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/client"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
)

const serviceContainer = serviceNamePrefix + "container.ContainerService"

const (
	rpcContainerPut       = "Put"
	rpcContainerGet       = "Get"
	rpcContainerDel       = "Delete"
	rpcContainerList      = "List"
	rpcContainerSetEACL   = "SetExtendedACL"
	rpcContainerGetEACL   = "GetExtendedACL"
	rpcContainerUsedSpace = "AnnounceUsedSpace"
)

// PutContainer executes ContainerService.Put RPC.
func PutContainer(
	cli *client.Client,
	req *container.PutRequest,
	opts ...client.CallOption,
) (*container.PutResponse, error) {
	resp := new(container.PutResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerPut), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GetContainer executes ContainerService.Get RPC.
func GetContainer(
	cli *client.Client,
	req *container.GetRequest,
	opts ...client.CallOption,
) (*container.GetResponse, error) {
	resp := new(container.GetResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerGet), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteContainer executes ContainerService.Delete RPC.
func DeleteContainer(
	cli *client.Client,
	req *container.DeleteRequest,
	opts ...client.CallOption,
) (*container.PutResponse, error) {
	resp := new(container.PutResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerDel), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// ListContainers executes ContainerService.List RPC.
func ListContainers(
	cli *client.Client,
	req *container.ListRequest,
	opts ...client.CallOption,
) (*container.ListResponse, error) {
	resp := new(container.ListResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerList), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// SetEACL executes ContainerService.SetExtendedACL RPC.
func SetEACL(
	cli *client.Client,
	req *container.SetExtendedACLRequest,
	opts ...client.CallOption,
) (*container.PutResponse, error) {
	resp := new(container.PutResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerSetEACL), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GetEACL executes ContainerService.GetExtendedACL RPC.
func GetEACL(
	cli *client.Client,
	req *container.GetExtendedACLRequest,
	opts ...client.CallOption,
) (*container.GetExtendedACLResponse, error) {
	resp := new(container.GetExtendedACLResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerGetEACL), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// AnnounceUsedSpace executes ContainerService.AnnounceUsedSpace RPC.
func AnnounceUsedSpace(
	cli *client.Client,
	req *container.AnnounceUsedSpaceRequest,
	opts ...client.CallOption,
) (*container.PutResponse, error) {
	resp := new(container.PutResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceContainer, rpcContainerUsedSpace), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
