package object_test

import (
	"testing"

	objecttest "github.com/TrueCloudLab/frostfs-api-go/v2/object/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return objecttest.GenerateShortHeader(empty) },
		func(empty bool) message.Message { return objecttest.GenerateAttribute(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSplitHeader(empty) },
		func(empty bool) message.Message { return objecttest.GenerateHeader(empty) },
		func(empty bool) message.Message { return objecttest.GenerateObject(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSplitInfo(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRequest(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetObjectPartInit(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetObjectPartChunk(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetResponse(empty) },
		func(empty bool) message.Message { return objecttest.GeneratePutObjectPartInit(empty) },
		func(empty bool) message.Message { return objecttest.GeneratePutObjectPartChunk(empty) },
		func(empty bool) message.Message { return objecttest.GeneratePutRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GeneratePutRequest(empty) },
		func(empty bool) message.Message { return objecttest.GeneratePutResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GeneratePutResponse(empty) },
		func(empty bool) message.Message { return objecttest.GenerateDeleteRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateDeleteRequest(empty) },
		func(empty bool) message.Message { return objecttest.GenerateDeleteResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateDeleteResponse(empty) },
		func(empty bool) message.Message { return objecttest.GenerateHeadRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateHeadRequest(empty) },
		func(empty bool) message.Message { return objecttest.GenerateHeadResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateHeadResponse(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSearchFilter(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSearchRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSearchRequest(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSearchResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateSearchResponse(empty) },
		func(empty bool) message.Message { return objecttest.GenerateRange(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeRequest(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeResponse(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeHashRequestBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeHashRequest(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeHashResponseBody(empty) },
		func(empty bool) message.Message { return objecttest.GenerateGetRangeHashResponse(empty) },
		func(empty bool) message.Message { return objecttest.GenerateLock(empty) },
	)
}
