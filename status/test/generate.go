package statustest

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
)

// Detail returns status.Detail filled with static random values.
func Detail(empty bool) *status.Detail {
	m := new(status.Detail)

	if !empty {
		m.SetID(345)
		m.SetValue([]byte("value"))
	}

	return m
}

// Details returns several status.Detail messages filled with static random values.
func Details(empty bool) []status.Detail {
	var res []status.Detail

	if !empty {
		res = append(res,
			*Detail(false),
			*Detail(false),
		)
	}

	return res
}

// Status returns status.Status messages filled with static random values.
func Status(empty bool) *status.Status {
	m := new(status.Status)

	if !empty {
		m.SetCode(765)
		m.SetMessage("some string")
		status.SetStatusDetails(m, Details(false))
	}

	return m
}
