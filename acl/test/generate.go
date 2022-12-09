package acltest

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/acl"
	accountingtest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
)

func GenerateBearerToken(empty bool) *acl.BearerToken {
	m := new(acl.BearerToken)

	if !empty {
		m.SetBody(GenerateBearerTokenBody(false))
	}

	m.SetSignature(accountingtest.GenerateSignature(empty))

	return m
}

func GenerateBearerTokenBody(empty bool) *acl.BearerTokenBody {
	m := new(acl.BearerTokenBody)

	if !empty {
		m.SetOwnerID(accountingtest.GenerateOwnerID(false))
		m.SetEACL(GenerateTable(false))
		m.SetLifetime(GenerateTokenLifetime(false))
	}

	return m
}

func GenerateTable(empty bool) *acl.Table {
	m := new(acl.Table)

	if !empty {
		m.SetRecords(GenerateRecords(false))
		m.SetContainerID(accountingtest.GenerateContainerID(false))
	}

	m.SetVersion(accountingtest.GenerateVersion(empty))

	return m
}

func GenerateRecords(empty bool) []acl.Record {
	var rs []acl.Record

	if !empty {
		rs = append(rs,
			*GenerateRecord(false),
			*GenerateRecord(false),
		)
	}

	return rs
}

func GenerateRecord(empty bool) *acl.Record {
	m := new(acl.Record)

	if !empty {
		m.SetAction(acl.ActionAllow)
		m.SetOperation(acl.OperationGet)
		m.SetFilters(GenerateFilters(false))
		m.SetTargets(GenerateTargets(false))
	}

	return m
}

func GenerateFilters(empty bool) []acl.HeaderFilter {
	var fs []acl.HeaderFilter

	if !empty {
		fs = append(fs,
			*GenerateFilter(false),
			*GenerateFilter(false),
		)
	}

	return fs
}

func GenerateFilter(empty bool) *acl.HeaderFilter {
	m := new(acl.HeaderFilter)

	if !empty {
		m.SetKey("key")
		m.SetValue("val")
		m.SetHeaderType(acl.HeaderTypeRequest)
		m.SetMatchType(acl.MatchTypeStringEqual)
	}

	return m
}

func GenerateTargets(empty bool) []acl.Target {
	var ts []acl.Target

	if !empty {
		ts = append(ts,
			*GenerateTarget(false),
			*GenerateTarget(false),
		)
	}

	return ts
}

func GenerateTarget(empty bool) *acl.Target {
	m := new(acl.Target)

	if !empty {
		m.SetRole(acl.RoleSystem)
		m.SetKeys([][]byte{{1}, {2}})
	}

	return m
}

func GenerateTokenLifetime(empty bool) *acl.TokenLifetime {
	m := new(acl.TokenLifetime)

	if !empty {
		m.SetExp(1)
		m.SetIat(2)
		m.SetExp(3)
	}

	return m
}
