package acl

import (
	acl "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

// RoleToGRPCField converts unified role enum into grpc enum.
func RoleToGRPCField(t Role) acl.Role {
	switch t {
	case RoleUser:
		return acl.Role_USER
	case RoleSystem:
		return acl.Role_SYSTEM
	case RoleOthers:
		return acl.Role_OTHERS
	default:
		return acl.Role_ROLE_UNSPECIFIED
	}
}

// RoleFromGRPCField converts grpc enum into unified role enum.
func RoleFromGRPCField(t acl.Role) Role {
	switch t {
	case acl.Role_USER:
		return RoleUser
	case acl.Role_SYSTEM:
		return RoleSystem
	case acl.Role_OTHERS:
		return RoleOthers
	default:
		return RoleUnknown
	}
}

// OperationToGRPCField converts unified operation enum into grpc enum.
func OperationToGRPCField(t Operation) acl.Operation {
	switch t {
	case OperationPut:
		return acl.Operation_PUT
	case OperationDelete:
		return acl.Operation_DELETE
	case OperationGet:
		return acl.Operation_GET
	case OperationHead:
		return acl.Operation_HEAD
	case OperationSearch:
		return acl.Operation_SEARCH
	case OperationRange:
		return acl.Operation_GETRANGE
	case OperationRangeHash:
		return acl.Operation_GETRANGEHASH
	default:
		return acl.Operation_OPERATION_UNSPECIFIED
	}
}

// OperationFromGRPCField converts grpc enum into unified operation enum.
func OperationFromGRPCField(t acl.Operation) Operation {
	switch t {
	case acl.Operation_PUT:
		return OperationPut
	case acl.Operation_DELETE:
		return OperationDelete
	case acl.Operation_GET:
		return OperationGet
	case acl.Operation_HEAD:
		return OperationHead
	case acl.Operation_SEARCH:
		return OperationSearch
	case acl.Operation_GETRANGE:
		return OperationRange
	case acl.Operation_GETRANGEHASH:
		return OperationRangeHash
	default:
		return OperationUnknown
	}
}

// ActionToGRPCField converts unified action enum into grpc enum.
func ActionToGRPCField(t Action) acl.Action {
	switch t {
	case ActionDeny:
		return acl.Action_DENY
	case ActionAllow:
		return acl.Action_ALLOW
	default:
		return acl.Action_ACTION_UNSPECIFIED
	}
}

// ActionFromGRPCField converts grpc enum into unified action enum.
func ActionFromGRPCField(t acl.Action) Action {
	switch t {
	case acl.Action_DENY:
		return ActionDeny
	case acl.Action_ALLOW:
		return ActionAllow
	default:
		return ActionUnknown
	}
}

// HeaderTypeToGRPCField converts unified header type enum into grpc enum.
func HeaderTypeToGRPCField(t HeaderType) acl.HeaderType {
	switch t {
	case HeaderTypeRequest:
		return acl.HeaderType_REQUEST
	case HeaderTypeObject:
		return acl.HeaderType_OBJECT
	case HeaderTypeService:
		return acl.HeaderType_SERVICE
	default:
		return acl.HeaderType_HEADER_UNSPECIFIED
	}
}

// HeaderTypeFromGRPCField converts grpc enum into unified header type enum.
func HeaderTypeFromGRPCField(t acl.HeaderType) HeaderType {
	switch t {
	case acl.HeaderType_REQUEST:
		return HeaderTypeRequest
	case acl.HeaderType_OBJECT:
		return HeaderTypeObject
	case acl.HeaderType_SERVICE:
		return HeaderTypeService
	default:
		return HeaderTypeUnknown
	}
}

// MatchTypeToGRPCField converts unified match type enum into grpc enum.
func MatchTypeToGRPCField(t MatchType) acl.MatchType {
	switch t {
	case MatchTypeStringEqual:
		return acl.MatchType_STRING_EQUAL
	case MatchTypeStringNotEqual:
		return acl.MatchType_STRING_NOT_EQUAL
	default:
		return acl.MatchType_MATCH_TYPE_UNSPECIFIED
	}
}

// MatchTypeFromGRPCField converts grpc enum into unified match type enum.
func MatchTypeFromGRPCField(t acl.MatchType) MatchType {
	switch t {
	case acl.MatchType_STRING_EQUAL:
		return MatchTypeStringEqual
	case acl.MatchType_STRING_NOT_EQUAL:
		return MatchTypeStringNotEqual
	default:
		return MatchTypeUnknown
	}
}

func (f *HeaderFilter) ToGRPCMessage() grpc.Message {
	var m *acl.EACLRecord_Filter

	if f != nil {
		m = new(acl.EACLRecord_Filter)

		m.SetKey(f.key)
		m.SetValue(f.value)
		m.SetHeader(HeaderTypeToGRPCField(f.hdrType))
		m.SetMatchType(MatchTypeToGRPCField(f.matchType))
	}

	return m
}

func (f *HeaderFilter) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.EACLRecord_Filter)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	f.key = v.GetKey()
	f.value = v.GetValue()
	f.hdrType = HeaderTypeFromGRPCField(v.GetHeaderType())
	f.matchType = MatchTypeFromGRPCField(v.GetMatchType())

	return nil
}

func HeaderFiltersToGRPC(fs []HeaderFilter) (res []*acl.EACLRecord_Filter) {
	if fs != nil {
		res = make([]*acl.EACLRecord_Filter, 0, len(fs))

		for i := range fs {
			res = append(res, fs[i].ToGRPCMessage().(*acl.EACLRecord_Filter))
		}
	}

	return
}

func HeaderFiltersFromGRPC(fs []*acl.EACLRecord_Filter) (res []HeaderFilter, err error) {
	if fs != nil {
		res = make([]HeaderFilter, len(fs))

		for i := range fs {
			if fs[i] != nil {
				err = res[i].FromGRPCMessage(fs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (t *Target) ToGRPCMessage() grpc.Message {
	var m *acl.EACLRecord_Target

	if t != nil {
		m = new(acl.EACLRecord_Target)

		m.SetRole(RoleToGRPCField(t.role))
		m.SetKeys(t.keys)
	}

	return m
}

func (t *Target) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.EACLRecord_Target)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	t.role = RoleFromGRPCField(v.GetRole())
	t.keys = v.GetKeys()

	return nil
}

func TargetsToGRPC(ts []Target) (res []*acl.EACLRecord_Target) {
	if ts != nil {
		res = make([]*acl.EACLRecord_Target, 0, len(ts))

		for i := range ts {
			res = append(res, ts[i].ToGRPCMessage().(*acl.EACLRecord_Target))
		}
	}

	return
}

func TargetsFromGRPC(fs []*acl.EACLRecord_Target) (res []Target, err error) {
	if fs != nil {
		res = make([]Target, len(fs))

		for i := range fs {
			if fs[i] != nil {
				err = res[i].FromGRPCMessage(fs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (r *Record) ToGRPCMessage() grpc.Message {
	var m *acl.EACLRecord

	if r != nil {
		m = new(acl.EACLRecord)

		m.SetOperation(OperationToGRPCField(r.op))
		m.SetAction(ActionToGRPCField(r.action))
		m.SetFilters(HeaderFiltersToGRPC(r.filters))
		m.SetTargets(TargetsToGRPC(r.targets))
	}

	return m
}

func (r *Record) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.EACLRecord)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	r.filters, err = HeaderFiltersFromGRPC(v.GetFilters())
	if err != nil {
		return err
	}

	r.targets, err = TargetsFromGRPC(v.GetTargets())
	if err != nil {
		return err
	}

	r.op = OperationFromGRPCField(v.GetOperation())
	r.action = ActionFromGRPCField(v.GetAction())

	return nil
}

func RecordsToGRPC(ts []Record) (res []*acl.EACLRecord) {
	if ts != nil {
		res = make([]*acl.EACLRecord, 0, len(ts))

		for i := range ts {
			res = append(res, ts[i].ToGRPCMessage().(*acl.EACLRecord))
		}
	}

	return
}

func RecordsFromGRPC(fs []*acl.EACLRecord) (res []Record, err error) {
	if fs != nil {
		res = make([]Record, len(fs))

		for i := range fs {
			if fs[i] != nil {
				err = res[i].FromGRPCMessage(fs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (t *Table) ToGRPCMessage() grpc.Message {
	var m *acl.EACLTable

	if t != nil {
		m = new(acl.EACLTable)

		m.SetVersion(t.version.ToGRPCMessage().(*refsGRPC.Version))
		m.SetContainerId(t.cid.ToGRPCMessage().(*refsGRPC.ContainerID))
		m.SetRecords(RecordsToGRPC(t.records))
	}

	return m
}

func (t *Table) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.EACLTable)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	cid := v.GetContainerId()
	if cid == nil {
		t.cid = nil
	} else {
		if t.cid == nil {
			t.cid = new(refs.ContainerID)
		}

		err = t.cid.FromGRPCMessage(cid)
		if err != nil {
			return err
		}
	}

	version := v.GetVersion()
	if version == nil {
		t.version = nil
	} else {
		if t.version == nil {
			t.version = new(refs.Version)
		}

		err = t.version.FromGRPCMessage(version)
		if err != nil {
			return err
		}
	}

	t.records, err = RecordsFromGRPC(v.GetRecords())

	return err
}

func (l *TokenLifetime) ToGRPCMessage() grpc.Message {
	var m *acl.BearerToken_Body_TokenLifetime

	if l != nil {
		m = new(acl.BearerToken_Body_TokenLifetime)

		m.SetExp(l.exp)
		m.SetIat(l.iat)
		m.SetNbf(l.nbf)
	}

	return m
}

func (l *TokenLifetime) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.BearerToken_Body_TokenLifetime)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	l.exp = v.GetExp()
	l.iat = v.GetIat()
	l.nbf = v.GetNbf()

	return nil
}

func (bt *BearerTokenBody) ToGRPCMessage() grpc.Message {
	var m *acl.BearerToken_Body

	if bt != nil {
		m = new(acl.BearerToken_Body)

		m.SetOwnerId(bt.ownerID.ToGRPCMessage().(*refsGRPC.OwnerID))
		m.SetLifetime(bt.lifetime.ToGRPCMessage().(*acl.BearerToken_Body_TokenLifetime))
		m.SetEaclTable(bt.eacl.ToGRPCMessage().(*acl.EACLTable))
		m.SetImpersonate(bt.impersonate)
	}

	return m
}

func (bt *BearerTokenBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.BearerToken_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	ownerID := v.GetOwnerId()
	if ownerID == nil {
		bt.ownerID = nil
	} else {
		if bt.ownerID == nil {
			bt.ownerID = new(refs.OwnerID)
		}

		err = bt.ownerID.FromGRPCMessage(ownerID)
		if err != nil {
			return err
		}
	}

	lifetime := v.GetLifetime()
	if lifetime == nil {
		bt.lifetime = nil
	} else {
		if bt.lifetime == nil {
			bt.lifetime = new(TokenLifetime)
		}

		err = bt.lifetime.FromGRPCMessage(lifetime)
		if err != nil {
			return err
		}
	}

	eacl := v.GetEaclTable()
	if eacl == nil {
		bt.eacl = nil
	} else {
		if bt.eacl == nil {
			bt.eacl = new(Table)
		}

		err = bt.eacl.FromGRPCMessage(eacl)
	}

	bt.impersonate = v.GetAllowImpersonate()

	return err
}

func (bt *BearerToken) ToGRPCMessage() grpc.Message {
	var m *acl.BearerToken

	if bt != nil {
		m = new(acl.BearerToken)

		m.SetBody(bt.body.ToGRPCMessage().(*acl.BearerToken_Body))
		m.SetSignature(bt.sig.ToGRPCMessage().(*refsGRPC.Signature))
	}

	return m
}

func (bt *BearerToken) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*acl.BearerToken)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		bt.body = nil
	} else {
		if bt.body == nil {
			bt.body = new(BearerTokenBody)
		}

		err = bt.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	sig := v.GetSignature()
	if sig == nil {
		bt.sig = nil
	} else {
		if bt.sig == nil {
			bt.sig = new(refs.Signature)
		}

		err = bt.sig.FromGRPCMessage(sig)
	}

	return err
}
