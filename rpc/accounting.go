package rpc

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/accounting"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/client"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
)

const serviceAccounting = serviceNamePrefix + "accounting.AccountingService"

const (
	rpcAccountingBalance = "Balance"
)

// Balance executes AccountingService.Balance RPC.
func Balance(
	cli *client.Client,
	req *accounting.BalanceRequest,
	opts ...client.CallOption,
) (*accounting.BalanceResponse, error) {
	resp := new(accounting.BalanceResponse)

	err := client.SendUnary(cli, common.CallMethodInfoUnary(serviceAccounting, rpcAccountingBalance), req, resp, opts...)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
