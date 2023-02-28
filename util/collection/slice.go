package collection

import "golang.org/x/exp/constraints"

// Max finds maximum value of items.
func Max[T constraints.Ordered](items ...T) T {
	if len(items) == 0 {
		panic("failed to get max value: empty slice")
	}
	result := items[0]
	for i := 1; i < len(items); i++ {
		if items[i] > result {
			result = items[i]
		}
	}
	return result
}
