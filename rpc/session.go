package rpc

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/client"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
)

const serviceSession = serviceNamePrefix + "session.SessionService"

const (
	rpcSessionCreate = "Create"
)

func CreateSession(
	cli *client.Client,
	req *session.CreateRequest,
	opts ...client.CallOption,
) (*session.CreateResponse, error) {
	resp := new(session.CreateResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceSession, rpcSessionCreate), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
