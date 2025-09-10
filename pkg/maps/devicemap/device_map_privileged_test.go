// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)
}

func TestDeviceMap(t *testing.T) {
	setup(t)
	deviceMap, _ := newDeviceMap(hivetest.Lifecycle(t))
	t.Cleanup(func() {
		deviceMap.Map.Unpin()
	})

	randMAC01, _ := mac.GenerateRandMAC()
	mac01, err := randMAC01.Uint64()
	value01 := &DeviceValue{MAC: mac01}

	randMAC02, _ := mac.GenerateRandMAC()
	mac02, err := randMAC02.Uint64()
	require.NoError(t, err)
	value02 := &DeviceValue{MAC: mac02, L3: 1}
	key := &DeviceKey{IfIndex: uint32(10)}

	_, err = deviceMap.Map.Lookup(key)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)

	err = deviceMap.Map.Update(key, value01)
	require.NoError(t, err)

	info, err := deviceMap.Map.Lookup(key)
	require.NoError(t, err)
	require.Equal(t, mac01, info.(*DeviceValue).MAC)
	require.Equal(t, uint8(0), info.(*DeviceValue).L3)

	err = deviceMap.Map.Update(key, value02)
	require.NoError(t, err)

	info, err = deviceMap.Map.Lookup(key)
	require.NoError(t, err)
	require.Equal(t, mac02, info.(*DeviceValue).MAC)
	require.Equal(t, uint8(1), info.(*DeviceValue).L3)

	err = deviceMap.Map.Delete(key)
	require.NoError(t, err)

	_, err = deviceMap.Map.Lookup(key)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}
