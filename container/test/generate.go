package containertest

import (
	acltest "github.com/TrueCloudLab/frostfs-api-go/v2/acl/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/container"
	netmaptest "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/test"
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	sessiontest "github.com/TrueCloudLab/frostfs-api-go/v2/session/test"
)

func GenerateAttribute(empty bool) *container.Attribute {
	m := new(container.Attribute)

	if !empty {
		m.SetKey("key")
		m.SetValue("val")
	}

	return m
}

func GenerateAttributes(empty bool) []container.Attribute {
	var res []container.Attribute

	if !empty {
		res = append(res,
			*GenerateAttribute(false),
			*GenerateAttribute(false),
		)
	}

	return res
}

func GenerateContainer(empty bool) *container.Container {
	m := new(container.Container)

	if !empty {
		m.SetBasicACL(12)
		m.SetNonce([]byte{1, 2, 3})
		m.SetOwnerID(refstest.GenerateOwnerID(false))
		m.SetAttributes(GenerateAttributes(false))
		m.SetPlacementPolicy(netmaptest.GeneratePlacementPolicy(false))
	}

	m.SetVersion(refstest.GenerateVersion(empty))

	return m
}

func GeneratePutRequestBody(empty bool) *container.PutRequestBody {
	m := new(container.PutRequestBody)

	if !empty {
		m.SetContainer(GenerateContainer(false))
	}

	m.SetSignature(refstest.GenerateSignature(empty))

	return m
}

func GeneratePutRequest(empty bool) *container.PutRequest {
	m := new(container.PutRequest)

	if !empty {
		m.SetBody(GeneratePutRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GeneratePutResponseBody(empty bool) *container.PutResponseBody {
	m := new(container.PutResponseBody)

	if !empty {
		m.SetContainerID(refstest.GenerateContainerID(false))
	}

	return m
}

func GeneratePutResponse(empty bool) *container.PutResponse {
	m := new(container.PutResponse)

	if !empty {
		m.SetBody(GeneratePutResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateGetRequestBody(empty bool) *container.GetRequestBody {
	m := new(container.GetRequestBody)

	if !empty {
		m.SetContainerID(refstest.GenerateContainerID(false))
	}

	return m
}

func GenerateGetRequest(empty bool) *container.GetRequest {
	m := new(container.GetRequest)

	if !empty {
		m.SetBody(GenerateGetRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateGetResponseBody(empty bool) *container.GetResponseBody {
	m := new(container.GetResponseBody)

	if !empty {
		m.SetContainer(GenerateContainer(false))
	}

	m.SetSignature(refstest.GenerateSignature(empty))
	m.SetSessionToken(sessiontest.GenerateSessionToken(empty))

	return m
}

func GenerateGetResponse(empty bool) *container.GetResponse {
	m := new(container.GetResponse)

	if !empty {
		m.SetBody(GenerateGetResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateDeleteRequestBody(empty bool) *container.DeleteRequestBody {
	m := new(container.DeleteRequestBody)

	if !empty {
		m.SetContainerID(refstest.GenerateContainerID(false))
	}

	m.SetSignature(refstest.GenerateSignature(empty))

	return m
}

func GenerateDeleteRequest(empty bool) *container.DeleteRequest {
	m := new(container.DeleteRequest)

	if !empty {
		m.SetBody(GenerateDeleteRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateDeleteResponseBody(empty bool) *container.DeleteResponseBody {
	m := new(container.DeleteResponseBody)

	return m
}

func GenerateDeleteResponse(empty bool) *container.DeleteResponse {
	m := new(container.DeleteResponse)

	if !empty {
		m.SetBody(GenerateDeleteResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateListRequestBody(empty bool) *container.ListRequestBody {
	m := new(container.ListRequestBody)

	if !empty {
		m.SetOwnerID(refstest.GenerateOwnerID(false))
	}

	return m
}

func GenerateListRequest(empty bool) *container.ListRequest {
	m := new(container.ListRequest)

	if !empty {
		m.SetBody(GenerateListRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateListResponseBody(empty bool) *container.ListResponseBody {
	m := new(container.ListResponseBody)

	if !empty {
		m.SetContainerIDs(refstest.GenerateContainerIDs(false))
	}

	return m
}

func GenerateListResponse(empty bool) *container.ListResponse {
	m := new(container.ListResponse)

	if !empty {
		m.SetBody(GenerateListResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateSetExtendedACLRequestBody(empty bool) *container.SetExtendedACLRequestBody {
	m := new(container.SetExtendedACLRequestBody)

	if !empty {
		m.SetEACL(acltest.GenerateTable(false))
	}

	m.SetSignature(refstest.GenerateSignature(empty))

	return m
}

func GenerateSetExtendedACLRequest(empty bool) *container.SetExtendedACLRequest {
	m := new(container.SetExtendedACLRequest)

	if !empty {
		m.SetBody(GenerateSetExtendedACLRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateSetExtendedACLResponseBody(empty bool) *container.SetExtendedACLResponseBody {
	m := new(container.SetExtendedACLResponseBody)

	return m
}

func GenerateSetExtendedACLResponse(empty bool) *container.SetExtendedACLResponse {
	m := new(container.SetExtendedACLResponse)

	if !empty {
		m.SetBody(GenerateSetExtendedACLResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateGetExtendedACLRequestBody(empty bool) *container.GetExtendedACLRequestBody {
	m := new(container.GetExtendedACLRequestBody)

	if !empty {
		m.SetContainerID(refstest.GenerateContainerID(false))
	}

	return m
}

func GenerateGetExtendedACLRequest(empty bool) *container.GetExtendedACLRequest {
	m := new(container.GetExtendedACLRequest)

	if !empty {
		m.SetBody(GenerateGetExtendedACLRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateGetExtendedACLResponseBody(empty bool) *container.GetExtendedACLResponseBody {
	m := new(container.GetExtendedACLResponseBody)

	if !empty {
		m.SetEACL(acltest.GenerateTable(false))
	}

	m.SetSignature(refstest.GenerateSignature(empty))
	m.SetSessionToken(sessiontest.GenerateSessionToken(empty))

	return m
}

func GenerateGetExtendedACLResponse(empty bool) *container.GetExtendedACLResponse {
	m := new(container.GetExtendedACLResponse)

	if !empty {
		m.SetBody(GenerateGetExtendedACLResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateUsedSpaceAnnouncement(empty bool) *container.UsedSpaceAnnouncement {
	m := new(container.UsedSpaceAnnouncement)

	if !empty {
		m.SetContainerID(refstest.GenerateContainerID(false))
		m.SetEpoch(1)
		m.SetUsedSpace(2)
	}

	return m
}

func GenerateUsedSpaceAnnouncements(empty bool) []container.UsedSpaceAnnouncement {
	var res []container.UsedSpaceAnnouncement

	if !empty {
		res = append(res,
			*GenerateUsedSpaceAnnouncement(false),
			*GenerateUsedSpaceAnnouncement(false),
		)
	}

	return res
}

func GenerateAnnounceUsedSpaceRequestBody(empty bool) *container.AnnounceUsedSpaceRequestBody {
	m := new(container.AnnounceUsedSpaceRequestBody)

	if !empty {
		m.SetAnnouncements(GenerateUsedSpaceAnnouncements(false))
	}

	return m
}

func GenerateAnnounceUsedSpaceRequest(empty bool) *container.AnnounceUsedSpaceRequest {
	m := new(container.AnnounceUsedSpaceRequest)

	if !empty {
		m.SetBody(GenerateAnnounceUsedSpaceRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateAnnounceUsedSpaceResponseBody(empty bool) *container.AnnounceUsedSpaceResponseBody {
	m := new(container.AnnounceUsedSpaceResponseBody)

	return m
}

func GenerateAnnounceUsedSpaceResponse(empty bool) *container.AnnounceUsedSpaceResponse {
	m := new(container.AnnounceUsedSpaceResponse)

	if !empty {
		m.SetBody(GenerateAnnounceUsedSpaceResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}
