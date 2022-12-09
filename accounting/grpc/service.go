package accounting

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// SetOwnerId sets identifier of the account owner.
func (m *BalanceRequest_Body) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetBody sets body of the request.
func (m *BalanceRequest) SetBody(v *BalanceRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *BalanceRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *BalanceRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetBalance sets balance value of the response.
func (m *BalanceResponse_Body) SetBalance(v *Decimal) {
	m.Balance = v
}

// SetBody sets body of the response.
func (m *BalanceResponse) SetBody(v *BalanceResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *BalanceResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *BalanceResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}
