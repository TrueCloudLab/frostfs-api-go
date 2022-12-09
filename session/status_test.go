package session_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	statustest "github.com/TrueCloudLab/frostfs-api-go/v2/status/test"
)

func TestStatusCodes(t *testing.T) {
	statustest.TestCodes(t, session.LocalizeFailStatus, session.GlobalizeFail,
		session.StatusTokenNotFound, 4096,
		session.StatusTokenExpired, 4097,
	)
}
