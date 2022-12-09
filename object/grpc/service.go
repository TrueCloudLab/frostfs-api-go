package object

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// SetAddress sets address of the requested object.
func (m *GetRequest_Body) SetAddress(v *refs.Address) {
	m.Address = v
}

// SetRaw sets raw flag of the request.
func (m *GetRequest_Body) SetRaw(v bool) {
	m.Raw = v
}

// SetBody sets body of the request.
func (m *GetRequest) SetBody(v *GetRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *GetRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *GetRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetObjectId sets identifier of the object.
func (m *GetResponse_Body_Init) SetObjectId(v *refs.ObjectID) {
	m.ObjectId = v
}

// SetSignature sets signature of the object identifier.
func (m *GetResponse_Body_Init) SetSignature(v *refs.Signature) {
	m.Signature = v
}

// SetHeader sets header of the object.
func (m *GetResponse_Body_Init) SetHeader(v *Header) {
	m.Header = v
}

// GetChunk returns chunk of the object payload bytes.
func (m *GetResponse_Body_Chunk) GetChunk() []byte {
	if m != nil {
		return m.Chunk
	}

	return nil
}

// SetChunk sets chunk of the object payload bytes.
func (m *GetResponse_Body_Chunk) SetChunk(v []byte) {
	m.Chunk = v
}

// SetInit sets initial part of the object.
func (m *GetResponse_Body) SetInit(v *GetResponse_Body_Init) {
	m.ObjectPart = &GetResponse_Body_Init_{
		Init: v,
	}
}

// SetChunk sets part of the object payload.
func (m *GetResponse_Body) SetChunk(v *GetResponse_Body_Chunk) {
	m.ObjectPart = v
}

// SetSplitInfo sets part of the object payload.
func (m *GetResponse_Body) SetSplitInfo(v *SplitInfo) {
	m.ObjectPart = &GetResponse_Body_SplitInfo{
		SplitInfo: v,
	}
}

// SetBody sets body of the response.
func (m *GetResponse) SetBody(v *GetResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *GetResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *GetResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetObjectId sets identifier of the object.
func (m *PutRequest_Body_Init) SetObjectId(v *refs.ObjectID) {
	m.ObjectId = v
}

// SetSignature sets signature of the object identifier.
func (m *PutRequest_Body_Init) SetSignature(v *refs.Signature) {
	m.Signature = v
}

// SetHeader sets header of the object.
func (m *PutRequest_Body_Init) SetHeader(v *Header) {
	m.Header = v
}

// SetCopiesNumber sets number of the copies to save.
func (m *PutRequest_Body_Init) SetCopiesNumber(v uint32) {
	m.CopiesNumber = v
}

// GetChunk returns chunk of the object payload bytes.
func (m *PutRequest_Body_Chunk) GetChunk() []byte {
	if m != nil {
		return m.Chunk
	}

	return nil
}

// SetChunk sets chunk of the object payload bytes.
func (m *PutRequest_Body_Chunk) SetChunk(v []byte) {
	m.Chunk = v
}

// SetInit sets initial part of the object.
func (m *PutRequest_Body) SetInit(v *PutRequest_Body_Init) {
	m.ObjectPart = &PutRequest_Body_Init_{
		Init: v,
	}
}

// SetChunk sets part of the object payload.
func (m *PutRequest_Body) SetChunk(v *PutRequest_Body_Chunk) {
	m.ObjectPart = v
}

// SetBody sets body of the request.
func (m *PutRequest) SetBody(v *PutRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *PutRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *PutRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetObjectId sets identifier of the saved object.
func (m *PutResponse_Body) SetObjectId(v *refs.ObjectID) {
	m.ObjectId = v
}

// SetBody sets body of the response.
func (m *PutResponse) SetBody(v *PutResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *PutResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *PutResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetAddress sets address of the object to delete.
func (m *DeleteRequest_Body) SetAddress(v *refs.Address) {
	m.Address = v
}

// SetBody sets body of the request.
func (m *DeleteRequest) SetBody(v *DeleteRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *DeleteRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *DeleteRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetTombstone sets tombstone address.
func (x *DeleteResponse_Body) SetTombstone(v *refs.Address) {
	x.Tombstone = v
}

// SetBody sets body of the response.
func (m *DeleteResponse) SetBody(v *DeleteResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *DeleteResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *DeleteResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetAddress sets address of the object with the requested header.
func (m *HeadRequest_Body) SetAddress(v *refs.Address) {
	m.Address = v
}

// SetMainOnly sets flag to return the minimal header subset.
func (m *HeadRequest_Body) SetMainOnly(v bool) {
	m.MainOnly = v
}

// SetRaw sets raw flag of the request.
func (m *HeadRequest_Body) SetRaw(v bool) {
	m.Raw = v
}

// SetBody sets body of the request.
func (m *HeadRequest) SetBody(v *HeadRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *HeadRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *HeadRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetHeader sets object header.
func (m *HeaderWithSignature) SetHeader(v *Header) {
	m.Header = v
}

// SetSignature of the header.
func (m *HeaderWithSignature) SetSignature(v *refs.Signature) {
	m.Signature = v
}

// SetHeader sets full header of the object.
func (m *HeadResponse_Body) SetHeader(v *HeaderWithSignature) {
	m.Head = &HeadResponse_Body_Header{
		Header: v,
	}
}

// SetShortHeader sets short header of the object.
func (m *HeadResponse_Body) SetShortHeader(v *ShortHeader) {
	m.Head = &HeadResponse_Body_ShortHeader{
		ShortHeader: v,
	}
}

// SetSplitInfo sets meta info about split hierarchy of the object.
func (m *HeadResponse_Body) SetSplitInfo(v *SplitInfo) {
	m.Head = &HeadResponse_Body_SplitInfo{
		SplitInfo: v,
	}
}

// SetBody sets body of the response.
func (m *HeadResponse) SetBody(v *HeadResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *HeadResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *HeadResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetMatchType sets match type of the filter.
func (m *SearchRequest_Body_Filter) SetMatchType(v MatchType) {
	m.MatchType = v
}

// SetKey sets key to the filtering header.
func (m *SearchRequest_Body_Filter) SetKey(v string) {
	m.Key = v
}

// SetValue sets value of the filtering header.
func (m *SearchRequest_Body_Filter) SetValue(v string) {
	m.Value = v
}

// SetVersion sets version of the search query.
func (m *SearchRequest_Body) SetVersion(v uint32) {
	m.Version = v
}

// SetFilters sets list of the query filters.
func (m *SearchRequest_Body) SetFilters(v []*SearchRequest_Body_Filter) {
	m.Filters = v
}

// SetContainerId sets container ID of the search requets.
func (m *SearchRequest_Body) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetBody sets body of the request.
func (m *SearchRequest) SetBody(v *SearchRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *SearchRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *SearchRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetIdList sets list of the identifiers of the matched objects.
func (m *SearchResponse_Body) SetIdList(v []*refs.ObjectID) {
	m.IdList = v
}

// SetBody sets body of the response.
func (m *SearchResponse) SetBody(v *SearchResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *SearchResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *SearchResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetOffset sets offset of the payload range.
func (m *Range) SetOffset(v uint64) {
	m.Offset = v
}

// SetLength sets length of the payload range.
func (m *Range) SetLength(v uint64) {
	m.Length = v
}

// SetAddress sets address of the object with the request payload range.
func (m *GetRangeRequest_Body) SetAddress(v *refs.Address) {
	m.Address = v
}

// SetRange sets range of the object payload.
func (m *GetRangeRequest_Body) SetRange(v *Range) {
	m.Range = v
}

// SetRaw sets raw flag of the request.
func (m *GetRangeRequest_Body) SetRaw(v bool) {
	m.Raw = v
}

// SetBody sets body of the request.
func (m *GetRangeRequest) SetBody(v *GetRangeRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *GetRangeRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *GetRangeRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// GetChunk returns chunk of the object payload range bytes.
func (m *GetRangeResponse_Body_Chunk) GetChunk() []byte {
	if m != nil {
		return m.Chunk
	}

	return nil
}

// SetChunk sets chunk of the object payload range bytes.
func (m *GetRangeResponse_Body_Chunk) SetChunk(v []byte) {
	m.Chunk = v
}

// SetChunk sets chunk of the object payload.
func (m *GetRangeResponse_Body) SetChunk(v *GetRangeResponse_Body_Chunk) {
	m.RangePart = v
}

// SetSplitInfo sets meta info about split hierarchy of the object.
func (m *GetRangeResponse_Body) SetSplitInfo(v *SplitInfo) {
	m.RangePart = &GetRangeResponse_Body_SplitInfo{
		SplitInfo: v,
	}
}

// SetBody sets body of the response.
func (m *GetRangeResponse) SetBody(v *GetRangeResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *GetRangeResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *GetRangeResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetAddress sets address of the object with the request payload range.
func (m *GetRangeHashRequest_Body) SetAddress(v *refs.Address) {
	m.Address = v
}

// SetRanges sets list of the ranges of the object payload.
func (m *GetRangeHashRequest_Body) SetRanges(v []*Range) {
	m.Ranges = v
}

// SetSalt sets salt for the object payload ranges.
func (m *GetRangeHashRequest_Body) SetSalt(v []byte) {
	m.Salt = v
}

// Set sets salt for the object payload ranges.
func (m *GetRangeHashRequest_Body) SetType(v refs.ChecksumType) {
	m.Type = v
}

// SetBody sets body of the request.
func (m *GetRangeHashRequest) SetBody(v *GetRangeHashRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *GetRangeHashRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *GetRangeHashRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetHashList returns list of the range hashes.
func (m *GetRangeHashResponse_Body) SetHashList(v [][]byte) {
	m.HashList = v
}

// SetHashList returns list of the range hashes.
func (m *GetRangeHashResponse_Body) SetType(v refs.ChecksumType) {
	m.Type = v
}

// SetBody sets body of the response.
func (m *GetRangeHashResponse) SetBody(v *GetRangeHashResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *GetRangeHashResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *GetRangeHashResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}
