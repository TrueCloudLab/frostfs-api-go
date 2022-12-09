package netmap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
)

// prefix of keys to subnet attributes.
const attrSubnetPrefix = "__NEOFS__SUBNET_"

const (
	// subnet attribute's value denoting subnet entry
	attrSubnetValEntry = "True"

	// subnet attribute's value denoting subnet exit
	attrSubnetValExit = "False"
)

// NodeSubnetInfo groups information about subnet which can be written to NodeInfo.
//
// Zero value represents entry to zero subnet.
type NodeSubnetInfo struct {
	exit bool

	id *refs.SubnetID
}

// Enabled returns true iff subnet membership is enabled for the node.
func (x NodeSubnetInfo) Enabled() bool {
	return !x.exit
}

// SetEntryFlag sets the subnet entry flag.
func (x *NodeSubnetInfo) SetEntryFlag(enters bool) {
	x.exit = !enters
}

// ID returns identifier of the subnet.
func (x NodeSubnetInfo) ID() *refs.SubnetID {
	return x.id
}

// SetID sets identifier of the subnet.
func (x *NodeSubnetInfo) SetID(id *refs.SubnetID) {
	x.id = id
}

func subnetAttributeKey(id *refs.SubnetID) string {
	txt, _ := id.MarshalText() // never returns an error

	return attrSubnetPrefix + string(txt)
}

// WriteSubnetInfo writes NodeSubnetInfo to NodeInfo via attributes. NodeInfo must not be nil.
//
// Existing subnet attributes are expected to be key-unique, otherwise undefined behavior.
//
// Does not add (removes existing) attribute if node:
//   - disables non-zero subnet;
//   - enables zero subnet.
//
// Attribute key is calculated from ID using format `__NEOFS__SUBNET_%s`.
// Attribute Value is:
//   - `True` if node enters the subnet;
//   - `False`, otherwise.
func WriteSubnetInfo(node *NodeInfo, info NodeSubnetInfo) {
	attrs := node.GetAttributes()

	id := info.ID()
	enters := info.Enabled()

	// calculate attribute key
	key := subnetAttributeKey(id)

	if refs.IsZeroSubnet(id) == enters {
		for i := range attrs {
			if attrs[i].GetKey() == key {
				attrs = append(attrs[:i], attrs[i+1:]...)
				break // attributes are expected to be key-unique
			}
		}
	} else {
		var val string

		if enters {
			val = attrSubnetValEntry
		} else {
			val = attrSubnetValExit
		}

		presented := false

		for i := range attrs {
			if attrs[i].GetKey() == key {
				attrs[i].SetValue(val)
				presented = true
			}
		}

		if !presented {
			index := len(attrs)
			attrs = append(attrs, Attribute{})
			attrs[index].SetKey(key)
			attrs[index].SetValue(val)
		}
	}

	node.SetAttributes(attrs)
}

// ErrRemoveSubnet is returned when a node needs to leave the subnet.
var ErrRemoveSubnet = errors.New("remove subnet")

var errNoSubnets = errors.New("no subnets")

// IterateSubnets iterates over all subnets the node belongs to and passes the IDs to f.
// Handler must not be nil.
//
// Subnet attributes are expected to be key-unique, otherwise undefined behavior.
//
// If f returns ErrRemoveSubnet, then removes subnet entry. Note that this leads to an instant mutation of NodeInfo.
// Breaks on any other non-nil error and returns it.
//
// Returns an error if any subnet attribute has wrong format.
// Returns an error if the node is not included in any subnet by the end of the loop.
func IterateSubnets(node *NodeInfo, f func(refs.SubnetID) error) error {
	attrs := node.GetAttributes()

	var (
		err     error
		id      refs.SubnetID
		entries uint

		zeroEntry = true
	)

	for i := 0; i < len(attrs); i++ { // range must not be used because of attrs mutation in body
		key := attrs[i].GetKey()

		// cut subnet ID string
		idTxt := strings.TrimPrefix(key, attrSubnetPrefix)
		if len(idTxt) == len(key) {
			// not a subnet attribute
			continue
		}

		// check value
		val := attrs[i].GetValue()
		if val != attrSubnetValExit && val != attrSubnetValEntry {
			return fmt.Errorf("invalid attribute value: %s", val)
		}

		// decode subnet ID
		if err = id.UnmarshalText([]byte(idTxt)); err != nil {
			return fmt.Errorf("invalid ID text: %w", err)
		}

		// update status of zero subnet
		isZero := refs.IsZeroSubnet(&id)

		if isZero {
			zeroEntry = val == attrSubnetValEntry
		}

		// continue to process only the subnets to which the node belongs
		if val == attrSubnetValExit {
			continue
		}

		// pass ID to the handler
		err = f(id)

		isRemoveErr := errors.Is(err, ErrRemoveSubnet)

		if err != nil && !isRemoveErr {
			return err
		}

		if isRemoveErr {
			if isZero {
				// we can't remove attribute of zero subnet because it means entry
				attrs[i].SetValue(attrSubnetValExit)
			} else {
				// we can set False or remove attribute, latter is more memory/network efficient.
				attrs = append(attrs[:i], attrs[i+1:]...)
				i--
			}

			continue
		}

		entries++
	}

	if zeroEntry {
		// missing attribute of zero subnet equivalent to entry
		refs.MakeZeroSubnet(&id)

		err = f(id)
		if err != nil {
			if !errors.Is(err, ErrRemoveSubnet) {
				return err
			}

			// zero subnet should be clearly removed with False value
			index := len(attrs)
			attrs = append(attrs, Attribute{})
			attrs[index].SetKey(subnetAttributeKey(&id))
			attrs[index].SetValue(attrSubnetValExit)
		} else {
			entries++
		}
	}

	if entries <= 0 {
		return errNoSubnets
	}

	node.SetAttributes(attrs)

	return nil
}
