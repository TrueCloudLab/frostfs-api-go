package rpc

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/reputation"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/client"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
)

const serviceReputation = serviceNamePrefix + "reputation.ReputationService"

const (
	rpcReputationAnnounceLocalTrust         = "AnnounceLocalTrust"
	rpcReputationAnnounceIntermediateResult = "AnnounceIntermediateResult"
)

// AnnounceLocalTrust executes ReputationService.AnnounceLocalTrust RPC.
func AnnounceLocalTrust(
	cli *client.Client,
	req *reputation.AnnounceLocalTrustRequest,
	opts ...client.CallOption,
) (*reputation.AnnounceLocalTrustResponse, error) {
	resp := new(reputation.AnnounceLocalTrustResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceReputation, rpcReputationAnnounceLocalTrust), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// AnnounceIntermediateResult executes ReputationService.AnnounceIntermediateResult RPC.
func AnnounceIntermediateResult(
	cli *client.Client,
	req *reputation.AnnounceIntermediateResultRequest,
	opts ...client.CallOption,
) (*reputation.AnnounceIntermediateResultResponse, error) {
	resp := new(reputation.AnnounceIntermediateResultResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceReputation, rpcReputationAnnounceIntermediateResult), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
