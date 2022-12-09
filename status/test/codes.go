package statustest

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
	"github.com/stretchr/testify/require"
)

// TestCodes checks mapping of status codes to the numbers.
// Args must be pairs (status.Code, int).
func TestCodes(t *testing.T,
	localizer func(*status.Code) bool,
	globalizer func(code *status.Code),
	vals ...interface{},
) {
	for i := 0; i < len(vals); i += 2 {
		c := vals[i].(status.Code)
		cp := c

		globalizer(&cp)
		require.True(t, cp.EqualNumber(uint32(vals[i+1].(int))), c)

		require.True(t, localizer(&cp), c)

		require.Equal(t, cp, c, c)
	}
}
