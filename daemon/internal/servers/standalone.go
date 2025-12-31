// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package servers

import (
	"context"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/snet"
)

// StandaloneDaemon implements the daemon.Connector interface by directly
// delegating to a DaemonEngine. This allows in-process usage of daemon
// functionality without going through gRPC.
type StandaloneDaemon struct {
	Engine *DaemonEngine
}

// TODO: NewStandaloneDaemon

// LocalIA returns the local ISD-AS number.
func (s *StandaloneDaemon) LocalIA(ctx context.Context) (addr.IA, error) {
	return s.Engine.LocalIA(ctx)
}

// PortRange returns the beginning and the end of the SCION/UDP endhost port range.
func (s *StandaloneDaemon) PortRange(ctx context.Context) (uint16, uint16, error) {
	return s.Engine.PortRange(ctx)
}

// Interfaces returns the map of interface identifiers to the underlay internal address.
func (s *StandaloneDaemon) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	return s.Engine.Interfaces(ctx)
}

// Paths requests from the daemon a set of end to end paths between the source and destination.
func (s *StandaloneDaemon) Paths(
	ctx context.Context,
	dst, src addr.IA,
	f daemon.PathReqFlags,
) ([]snet.Path, error) {
	return s.Engine.Paths(ctx, dst, src, f)
}

// ASInfo requests information about an AS. The zero IA returns local AS info.
func (s *StandaloneDaemon) ASInfo(ctx context.Context, ia addr.IA) (daemon.ASInfo, error) {
	return s.Engine.ASInfo(ctx, ia)
}

// SVCInfo requests information about addresses and ports of infrastructure services.
func (s *StandaloneDaemon) SVCInfo(
	ctx context.Context,
	_ []addr.SVC,
) (map[addr.SVC][]string, error) {
	uris, err := s.Engine.SVCInfo(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[addr.SVC][]string)
	if len(uris) > 0 {
		result[addr.SvcCS] = uris
	}
	return result, nil
}

// RevNotification sends a RevocationInfo message to the daemon.
func (s *StandaloneDaemon) RevNotification(
	ctx context.Context,
	revInfo *path_mgmt.RevInfo,
) error {
	return s.Engine.NotifyInterfaceDown(ctx, revInfo.RawIsdas, uint64(revInfo.IfID))
}

// DRKeyGetASHostKey requests an AS-Host Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta,
) (drkey.ASHostKey, error) {
	return s.Engine.DRKeyGetASHostKey(ctx, meta)
}

// DRKeyGetHostASKey requests a Host-AS Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta,
) (drkey.HostASKey, error) {
	return s.Engine.DRKeyGetHostASKey(ctx, meta)
}

// DRKeyGetHostHostKey requests a Host-Host Key from the daemon.
func (s *StandaloneDaemon) DRKeyGetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta,
) (drkey.HostHostKey, error) {
	return s.Engine.DRKeyGetHostHostKey(ctx, meta)
}

// Close is a no-op for the standalone daemon as there's no connection to close.
func (s *StandaloneDaemon) Close() error {
	return nil
}

// Compile-time assertion that StandaloneDaemon implements daemon.Connector.
var _ daemon.Connector = (*StandaloneDaemon)(nil)
