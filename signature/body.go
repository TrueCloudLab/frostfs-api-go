package signature

import (
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/accounting"
	"github.com/TrueCloudLab/frostfs-api-go/v2/container"
	"github.com/TrueCloudLab/frostfs-api-go/v2/netmap"
	"github.com/TrueCloudLab/frostfs-api-go/v2/object"
	"github.com/TrueCloudLab/frostfs-api-go/v2/reputation"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
)

func serviceMessageBody(req interface{}) stableMarshaler {
	switch v := req.(type) {
	default:
		panic(fmt.Sprintf("unsupported session message %T", req))

		/* Accounting */
	case *accounting.BalanceRequest:
		return v.GetBody()
	case *accounting.BalanceResponse:
		return v.GetBody()

		/* Session */
	case *session.CreateRequest:
		return v.GetBody()
	case *session.CreateResponse:
		return v.GetBody()

		/* Container */
	case *container.PutRequest:
		return v.GetBody()
	case *container.PutResponse:
		return v.GetBody()
	case *container.DeleteRequest:
		return v.GetBody()
	case *container.DeleteResponse:
		return v.GetBody()
	case *container.GetRequest:
		return v.GetBody()
	case *container.GetResponse:
		return v.GetBody()
	case *container.ListRequest:
		return v.GetBody()
	case *container.ListResponse:
		return v.GetBody()
	case *container.SetExtendedACLRequest:
		return v.GetBody()
	case *container.SetExtendedACLResponse:
		return v.GetBody()
	case *container.GetExtendedACLRequest:
		return v.GetBody()
	case *container.GetExtendedACLResponse:
		return v.GetBody()
	case *container.AnnounceUsedSpaceRequest:
		return v.GetBody()
	case *container.AnnounceUsedSpaceResponse:
		return v.GetBody()

		/* Object */
	case *object.PutRequest:
		return v.GetBody()
	case *object.PutResponse:
		return v.GetBody()
	case *object.GetRequest:
		return v.GetBody()
	case *object.GetResponse:
		return v.GetBody()
	case *object.HeadRequest:
		return v.GetBody()
	case *object.HeadResponse:
		return v.GetBody()
	case *object.SearchRequest:
		return v.GetBody()
	case *object.SearchResponse:
		return v.GetBody()
	case *object.DeleteRequest:
		return v.GetBody()
	case *object.DeleteResponse:
		return v.GetBody()
	case *object.GetRangeRequest:
		return v.GetBody()
	case *object.GetRangeResponse:
		return v.GetBody()
	case *object.GetRangeHashRequest:
		return v.GetBody()
	case *object.GetRangeHashResponse:
		return v.GetBody()

		/* Netmap */
	case *netmap.LocalNodeInfoRequest:
		return v.GetBody()
	case *netmap.LocalNodeInfoResponse:
		return v.GetBody()
	case *netmap.NetworkInfoRequest:
		return v.GetBody()
	case *netmap.NetworkInfoResponse:
		return v.GetBody()
	case *netmap.SnapshotRequest:
		return v.GetBody()
	case *netmap.SnapshotResponse:
		return v.GetBody()

		/* Reputation */
	case *reputation.AnnounceLocalTrustRequest:
		return v.GetBody()
	case *reputation.AnnounceLocalTrustResponse:
		return v.GetBody()
	case *reputation.AnnounceIntermediateResultRequest:
		return v.GetBody()
	case *reputation.AnnounceIntermediateResultResponse:
		return v.GetBody()
	}
}
