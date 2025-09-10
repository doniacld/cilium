// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

// Cell provides the devicemap.Map which contains information about device ifindexes and their macs.
var Cell = cell.Module(
	"device-map",
	"eBPF map which contains information about device ifindexes and their macs",

	cell.Provide(newDeviceMap),
)

func newDeviceMap(lc cell.Lifecycle) (bpf.MapOut[*Map], defines.NodeOut) {
	m := &Map{DeviceMap()}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error { return m.Close() },
	})

	nodeOut := defines.NodeOut{
		NodeDefines: defines.Map{
			"DEVICE_MAP_SIZE": fmt.Sprint(MapSize),
		},
	}

	return bpf.NewMapOut(Map(m)), nodeOut
}
