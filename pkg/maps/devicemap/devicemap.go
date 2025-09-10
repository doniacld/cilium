// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
)

const (
	MapName = "cilium_device_map"
	MapSize = 256
)

type DeviceKey struct {
	IfIndex uint32 `align:"ifindex"`
}

func (k *DeviceKey) String() string {
	return fmt.Sprintf("%d", int(k.IfIndex))
}

func (k *DeviceKey) New() bpf.MapKey { return &DeviceKey{} }

type DeviceValue struct {
	MAC mac.Uint64MAC `align:"mac"`
	L3  uint8         `align:"l3"`
	Pad [7]uint8      `align:"pad"`
}

func (v *DeviceValue) String() string {
	return fmt.Sprintf("%d, %d", int(v.MAC), int(v.L3))
}

func (v *DeviceValue) New() bpf.MapValue { return &DeviceValue{} }

type deviceMap struct {
	*bpf.Map
}

func DeviceMap() *bpf.Map {
	return bpf.NewMap(
		MapName,
		ebpf.Hash,
		&DeviceKey{},
		&DeviceValue{},
		MapSize,
		bpf.BPF_F_NO_PREALLOC,
	)
}

// TODO not sure if it's still relevant
//// LoadDeviceMap loads the pre-initialized device map for access.
//// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
//// It needs to initialized beforehand via the Cilium Agent.
//func LoadDeviceMap(logger *slog.Logger) (Map, error) {
//	bpfMap, err := ebpf.LoadRegisterMap(logger, MapName)
//	if err != nil {
//		return nil, fmt.Errorf("failed to load bpf map: %w", err)
//	}
//
//	return &deviceMap{bpfMap: bpfMap}, nil
//}
