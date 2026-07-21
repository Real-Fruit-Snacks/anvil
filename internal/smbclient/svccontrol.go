package smbclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mandiant/gopacket/pkg/dcerpc"
	"github.com/mandiant/gopacket/pkg/dcerpc/svcctl"
)

// Service control over MS-SCMR on the session's svcctl pipe — it rides the
// existing IPC$ connection, so no new channel (same discipline as
// EnumServices in services.go, whose openSCManager is reused here).
// pkg/dcerpc/svcctl's ServiceController is deliberately not used: services.go
// already found its enum path broken against real Windows, and hand-rolled
// calls keep the NDR layout under our control. Windows SCMR hand-packs its
// [out] LPBYTE buffers with inconsistent framing (see
// parseServiceConfigStartType), so every response parser here is defensive.

// Win32 error codes surfaced by SCMR that pkg/dcerpc/svcctl does not export.
const (
	win32InsufficientBuffer       uint32 = 122
	win32DependentServicesRunning uint32 = 1051
	win32InvalidServiceControl    uint32 = 1052
	win32ServiceDisabled          uint32 = 1058
	win32ServiceCannotAcceptCtrl  uint32 = 1061
)

// scConfigMaxBuf caps the RQueryServiceConfigW buffer (the IDL ranges
// cbBufSize to 1024*8).
const scConfigMaxBuf = 8 * 1024

// svcStateTimeout bounds the wait for a service to reach the target state
// after a start/stop request; svcPollInterval is the QueryServiceStatus
// cadence while waiting.
const (
	svcStateTimeout = 15 * time.Second
	svcPollInterval = 250 * time.Millisecond
)

// ServiceStartType is a service's configured start mode (MS-SCMR
// dwStartType).
type ServiceStartType uint32

const (
	ServiceStartBoot     ServiceStartType = svcctl.SERVICE_BOOT_START
	ServiceStartSystem   ServiceStartType = svcctl.SERVICE_SYSTEM_START
	ServiceStartAuto     ServiceStartType = svcctl.SERVICE_AUTO_START
	ServiceStartDemand   ServiceStartType = svcctl.SERVICE_DEMAND_START
	ServiceStartDisabled ServiceStartType = svcctl.SERVICE_DISABLED
)

// ParseServiceStartType maps a shell-friendly name to a ServiceStartType.
// Only the three modes an operator should set remotely are accepted; boot
// and system start are driver territory — readable via String but not
// settable through this surface.
func ParseServiceStartType(s string) (ServiceStartType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "disabled":
		return ServiceStartDisabled, nil
	case "demand", "manual":
		return ServiceStartDemand, nil
	case "auto", "automatic":
		return ServiceStartAuto, nil
	}
	return 0, fmt.Errorf("unknown start type %q (use disabled, demand, or auto)", s)
}

// String renders the start type for display.
func (t ServiceStartType) String() string {
	switch t {
	case ServiceStartBoot:
		return "boot"
	case ServiceStartSystem:
		return "system"
	case ServiceStartAuto:
		return "auto"
	case ServiceStartDemand:
		return "demand"
	case ServiceStartDisabled:
		return "disabled"
	}
	return fmt.Sprintf("unknown(0x%x)", uint32(t))
}

// ServiceConfig is a service's start type and live state, captured so the
// prior configuration can be recorded before a change and restored
// afterwards.
type ServiceConfig struct {
	Name      string
	StartType ServiceStartType
	State     uint32 // raw MS-SCMR state (svcctl.SERVICE_STOPPED / SERVICE_RUNNING / ...)
}

// StateString renders State for display (RUNNING, STOPPED, ...).
func (c ServiceConfig) StateString() string { return svcctl.GetServiceState(c.State) }

// StartService starts a Windows service and waits (up to svcStateTimeout)
// for it to reach RUNNING. An already-running service is success, not an
// error. A disabled service fails themed — set its start type first.
func (s *Session) StartService(name string) error {
	err := s.withService(name, svcctl.SERVICE_START|svcctl.SERVICE_QUERY_STATUS,
		func(rpc *dcerpc.Client, h []byte) error {
			if err := startServiceRPC(rpc, h); err != nil {
				return err
			}
			_, err := waitServiceState(rpc, h, svcctl.SERVICE_RUNNING, svcStateTimeout)
			return err
		})
	if err != nil {
		return fmt.Errorf("start %s: %v", name, err)
	}
	return nil
}

// StopService stops a Windows service and waits (up to svcStateTimeout) for
// it to reach STOPPED. An already-stopped service is success, not an error.
// Services that do not accept control requests fail themed.
func (s *Session) StopService(name string) error {
	err := s.withService(name, svcctl.SERVICE_STOP|svcctl.SERVICE_QUERY_STATUS,
		func(rpc *dcerpc.Client, h []byte) error {
			if err := stopServiceRPC(rpc, h); err != nil {
				return err
			}
			_, err := waitServiceState(rpc, h, svcctl.SERVICE_STOPPED, svcStateTimeout)
			return err
		})
	if err != nil {
		return fmt.Errorf("stop %s: %v", name, err)
	}
	return nil
}

// SetServiceStartType changes a service's configured start mode and reads
// the config back to verify the change took — a silent no-op is worse than
// an error.
func (s *Session) SetServiceStartType(name string, startType ServiceStartType) error {
	err := s.withService(name, svcctl.SERVICE_CHANGE_CONFIG|svcctl.SERVICE_QUERY_CONFIG,
		func(rpc *dcerpc.Client, h []byte) error {
			if err := changeServiceStartTypeRPC(rpc, h, startType); err != nil {
				return err
			}
			got, err := queryServiceConfigStartType(rpc, h)
			if err != nil {
				return fmt.Errorf("verify: %v", err)
			}
			if ServiceStartType(got) != startType {
				return fmt.Errorf("verify: start type is still %s after change", ServiceStartType(got))
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("config %s: %v", name, err)
	}
	return nil
}

// GetServiceConfig returns a service's start type and current state.
func (s *Session) GetServiceConfig(name string) (*ServiceConfig, error) {
	cfg := &ServiceConfig{Name: name}
	err := s.withService(name, svcctl.SERVICE_QUERY_CONFIG|svcctl.SERVICE_QUERY_STATUS,
		func(rpc *dcerpc.Client, h []byte) error {
			st, err := queryServiceConfigStartType(rpc, h)
			if err != nil {
				return err
			}
			cfg.StartType = ServiceStartType(st)
			state, err := queryServiceState(rpc, h)
			if err != nil {
				return err
			}
			cfg.State = state
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("config %s: %v", name, err)
	}
	return cfg, nil
}

// EnsureRemoteRegistry makes the RemoteRegistry service usable on the
// target: when disabled it is switched to demand-start, and when stopped it
// is started. The returned closure puts the prior state back (stops the
// service again, restores the disabled start type) and is idempotent.
//
// Contract for the shell: call lazily before the first winreg consumer
// (reg/samdump/lsadump), keep the restore closure, and call it at session
// exit. When RemoteRegistry was already running and enabled — the common
// case on a managed host — nothing is changed and restore is a no-op. Uses
// the svcctl pipe on the existing session; no new channel.
func (s *Session) EnsureRemoteRegistry() (restore func() error, err error) {
	const name = "RemoteRegistry"
	var prior ServiceConfig
	prior.Name = name
	started := false   // we started the service → restore stops it
	reenabled := false // we lifted SERVICE_DISABLED → restore re-disables

	err = s.withService(name,
		svcctl.SERVICE_QUERY_CONFIG|svcctl.SERVICE_QUERY_STATUS|svcctl.SERVICE_CHANGE_CONFIG|svcctl.SERVICE_START|svcctl.SERVICE_STOP,
		func(rpc *dcerpc.Client, h []byte) error {
			st, err := queryServiceConfigStartType(rpc, h)
			if err != nil {
				return err
			}
			prior.StartType = ServiceStartType(st)
			state, err := queryServiceState(rpc, h)
			if err != nil {
				return err
			}
			prior.State = state

			if prior.StartType == ServiceStartDisabled {
				if err := changeServiceStartTypeRPC(rpc, h, ServiceStartDemand); err != nil {
					return fmt.Errorf("service is disabled and could not be re-enabled: %v", err)
				}
				reenabled = true
			}
			if prior.State != svcctl.SERVICE_RUNNING {
				if err := startServiceRPC(rpc, h); err != nil {
					return err
				}
				if _, err := waitServiceState(rpc, h, svcctl.SERVICE_RUNNING, svcStateTimeout); err != nil {
					return err
				}
				started = true
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if !started && !reenabled {
		return func() error { return nil }, nil
	}

	var once sync.Once
	var restoreErr error
	restore = func() error {
		once.Do(func() {
			restoreErr = s.withService(name,
				svcctl.SERVICE_STOP|svcctl.SERVICE_QUERY_STATUS|svcctl.SERVICE_CHANGE_CONFIG,
				func(rpc *dcerpc.Client, h []byte) error {
					var problems []string
					if started {
						if err := stopServiceRPC(rpc, h); err != nil {
							problems = append(problems, fmt.Sprintf("stop: %v", err))
						} else if _, err := waitServiceState(rpc, h, svcctl.SERVICE_STOPPED, svcStateTimeout); err != nil {
							problems = append(problems, fmt.Sprintf("wait for stop: %v", err))
						}
					}
					if reenabled {
						if err := changeServiceStartTypeRPC(rpc, h, prior.StartType); err != nil {
							problems = append(problems, fmt.Sprintf("restore start type: %v", err))
						}
					}
					if len(problems) > 0 {
						return fmt.Errorf("RemoteRegistry not fully restored (%s)", strings.Join(problems, "; "))
					}
					return nil
				})
		})
		return restoreErr
	}
	return restore, nil
}

// withSCM opens the svcctl pipe on the session's IPC$, binds, and opens the
// SCM database; fn runs with the bound client and the SCM handle, and
// everything is torn down afterwards. Plain bind + plain calls, like
// EnumServices: SCMR over an authenticated SMB pipe needs no RPC-level auth,
// and CallAuthAuto faults with RPC_S_CANNOT_SUPPORT.
func (s *Session) withSCM(fn func(rpc *dcerpc.Client, scmHandle []byte) error) error {
	pipe, err := s.client.OpenPipe("svcctl")
	if err != nil {
		return mapSCMError(fmt.Errorf("open svcctl pipe: %v", err))
	}
	defer pipe.Close()

	rpc := dcerpc.NewClient(pipe)
	if err := rpc.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		return mapSCMError(fmt.Errorf("bind svcctl: %v", err))
	}

	scm, err := openSCManager(rpc) // services.go
	if err != nil {
		return mapSCMError(err)
	}
	defer closeServiceHandle(rpc, scm)

	return mapSCMError(fn(rpc, scm))
}

// withService layers a service open/close on withSCM, requesting only the
// access rights the operation needs.
func (s *Session) withService(name string, access uint32, fn func(rpc *dcerpc.Client, svcHandle []byte) error) error {
	return s.withSCM(func(rpc *dcerpc.Client, scm []byte) error {
		h, err := openService(rpc, scm, name, access)
		if err != nil {
			return err
		}
		defer closeServiceHandle(rpc, h)
		return fn(rpc, h)
	})
}

// openService calls ROpenServiceW (opnum 16) and returns the 20-byte service
// handle. lpServiceName marshals as a bare NDR conformant-varying string
// with no referent ID — impacket's WSTR and pkg/dcerpc/svcctl agree on the
// wire here (writeWideStringNDR is exec.go's helper).
func openService(rpc *dcerpc.Client, scmHandle []byte, name string, access uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(scmHandle)
	writeWideStringNDR(buf, name)
	binary.Write(buf, binary.LittleEndian, access)

	resp, err := rpc.Call(svcctl.OpROpenServiceW, buf.Bytes())
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("ROpenServiceW response too short (%d bytes)", len(resp))
	}
	if ret := binary.LittleEndian.Uint32(resp[20:24]); ret != 0 {
		return nil, svcRetError("ROpenServiceW", ret)
	}
	return resp[:20], nil
}

// closeServiceHandle best-effort closes an SCM or service handle
// (RCloseServiceHandle, opnum 0); teardown errors carry no signal.
func closeServiceHandle(rpc *dcerpc.Client, handle []byte) {
	_, _ = rpc.Call(svcctl.OpRCloseServiceHandle, handle)
}

// queryServiceState calls RQueryServiceStatus (opnum 6) and returns the raw
// dwCurrentState from the SERVICE_STATUS.
func queryServiceState(rpc *dcerpc.Client, svcHandle []byte) (uint32, error) {
	resp, err := rpc.Call(svcctl.OpRQueryServiceStatus, svcHandle)
	if err != nil {
		return 0, err
	}
	return parseServiceStatusState(resp)
}

// startServiceRPC calls RStartServiceW (opnum 19) with no arguments.
// ERROR_SERVICE_ALREADY_RUNNING is tolerated — the caller waits for RUNNING
// either way.
func startServiceRPC(rpc *dcerpc.Client, svcHandle []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(svcHandle)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // argc: no args
	binary.Write(buf, binary.LittleEndian, uint32(0)) // argv: NULL

	resp, err := rpc.Call(svcctl.OpRStartServiceW, buf.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < 4 {
		return fmt.Errorf("RStartServiceW response too short (%d bytes)", len(resp))
	}
	if ret := binary.LittleEndian.Uint32(resp[len(resp)-4:]); ret != 0 && ret != svcctl.ERROR_SERVICE_ALREADY_RUNNING {
		return svcRetError("RStartServiceW", ret)
	}
	return nil
}

// stopServiceRPC calls RControlService (opnum 1) with SERVICE_CONTROL_STOP.
// ERROR_SERVICE_NOT_ACTIVE is tolerated — the caller waits for STOPPED
// either way.
func stopServiceRPC(rpc *dcerpc.Client, svcHandle []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(svcHandle)
	binary.Write(buf, binary.LittleEndian, uint32(svcctl.SERVICE_CONTROL_STOP))

	resp, err := rpc.Call(svcctl.OpRControlService, buf.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < 4 {
		return fmt.Errorf("RControlService response too short (%d bytes)", len(resp))
	}
	if ret := binary.LittleEndian.Uint32(resp[len(resp)-4:]); ret != 0 && ret != svcctl.ERROR_SERVICE_NOT_ACTIVE {
		return svcRetError("RControlService", ret)
	}
	return nil
}

// changeServiceStartTypeRPC calls RChangeServiceConfigW (opnum 11) changing
// only dwStartType; every other field is SERVICE_NO_CHANGE or a NULL
// pointer. The request shape mirrors pkg/dcerpc/svcctl's ChangeServiceConfig
// (which is correct on the wire — it is that package's response parsing that
// is not trusted).
func changeServiceStartTypeRPC(rpc *dcerpc.Client, svcHandle []byte, startType ServiceStartType) error {
	buf := new(bytes.Buffer)
	buf.Write(svcHandle)
	binary.Write(buf, binary.LittleEndian, uint32(svcctl.SERVICE_NO_CHANGE)) // dwServiceType
	binary.Write(buf, binary.LittleEndian, uint32(startType))                // dwStartType
	binary.Write(buf, binary.LittleEndian, uint32(svcctl.SERVICE_NO_CHANGE)) // dwErrorControl
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpBinaryPathName NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpLoadOrderGroup NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpdwTagId NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpDependencies NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // dwDependSize
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpServiceStartName NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpPassword NULL
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // dwPwSize
	binary.Write(buf, binary.LittleEndian, uint32(0))                        // lpDisplayName NULL

	resp, err := rpc.Call(svcctl.OpRChangeServiceConfigW, buf.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < 4 {
		return fmt.Errorf("RChangeServiceConfigW response too short (%d bytes)", len(resp))
	}
	if ret := binary.LittleEndian.Uint32(resp[len(resp)-4:]); ret != 0 {
		return svcRetError("RChangeServiceConfigW", ret)
	}
	return nil
}

// queryServiceConfigStartType calls RQueryServiceConfigW (opnum 17) with the
// classic sizing dance — probe with cbBufSize=0, retry with the server's
// pcbBytesNeeded — and returns dwStartType from the config.
func queryServiceConfigStartType(rpc *dcerpc.Client, svcHandle []byte) (uint32, error) {
	call := func(size uint32) ([]byte, error) {
		buf := new(bytes.Buffer)
		buf.Write(svcHandle)
		binary.Write(buf, binary.LittleEndian, size)
		return rpc.Call(svcctl.OpRQueryServiceConfigW, buf.Bytes())
	}

	resp, err := call(0)
	if err != nil {
		return 0, err
	}
	needed, ret, err := parseServiceConfigTrailer(resp)
	if err != nil {
		return 0, err
	}
	switch ret {
	case 0:
		// Answered in full with cbBufSize=0 (tiny config) — parse as-is.
		return parseServiceConfigStartType(resp)
	case win32InsufficientBuffer:
		size := needed
		if size == 0 || size > scConfigMaxBuf {
			size = scConfigMaxBuf
		}
		resp, err := call(size)
		if err != nil {
			return 0, err
		}
		return parseServiceConfigStartType(resp)
	default:
		return 0, svcRetError("RQueryServiceConfigW", ret)
	}
}

// waitServiceState polls QueryServiceStatus until the service reaches want
// or the timeout expires. Pending states are a normal mid-transition and
// just keep the loop going; the last observed state is returned on timeout.
func waitServiceState(rpc *dcerpc.Client, svcHandle []byte, want uint32, timeout time.Duration) (uint32, error) {
	deadline := time.Now().Add(timeout)
	for {
		state, err := queryServiceState(rpc, svcHandle)
		if err != nil {
			return 0, err
		}
		if state == want {
			return state, nil
		}
		if time.Now().After(deadline) {
			return state, fmt.Errorf("timed out (%s) waiting for %s (still %s)",
				timeout, svcctl.GetServiceState(want), svcctl.GetServiceState(state))
		}
		time.Sleep(svcPollInterval)
	}
}

// parseServiceStatusState extracts dwCurrentState from an
// RQueryServiceStatus response: SERVICE_STATUS (28 bytes, state at offset 4)
// followed by ReturnValue.
func parseServiceStatusState(resp []byte) (uint32, error) {
	if len(resp) < 32 {
		return 0, fmt.Errorf("RQueryServiceStatus response too short (%d bytes)", len(resp))
	}
	if ret := binary.LittleEndian.Uint32(resp[len(resp)-4:]); ret != 0 {
		return 0, svcRetError("RQueryServiceStatus", ret)
	}
	return binary.LittleEndian.Uint32(resp[4:8]), nil
}

// parseServiceConfigTrailer reads pcbBytesNeeded and ReturnValue off the end
// of an RQueryServiceConfigW response. pcbBytesNeeded is a
// LPBOUNDED_DWORD_4K — an NDR pointer — so the trailer is referent(4) +
// value(4) + return code(4).
func parseServiceConfigTrailer(resp []byte) (needed, ret uint32, err error) {
	if len(resp) < 12 {
		return 0, 0, fmt.Errorf("RQueryServiceConfigW response too short (%d bytes)", len(resp))
	}
	return binary.LittleEndian.Uint32(resp[len(resp)-8 : len(resp)-4]),
		binary.LittleEndian.Uint32(resp[len(resp)-4:]), nil
}

// parseServiceConfigStartType extracts dwStartType from an
// RQueryServiceConfigW response. Windows SCMR hand-packs the [out]
// lpServiceConfig buffer as it does for EnumServicesStatusW (services.go),
// and the framing around the QUERY_SERVICE_CONFIGW fixed part varies between
// server implementations, so the fixed part's start is sniffed at offsets
// 0 (bare struct), 4 (referent only), and 8 (referent + conformant maxCount)
// — the first offset whose dwServiceType holds only valid service-type bits
// and whose dwStartType is in range wins. A pointer referent (0x00020000,
// ...) never satisfies that predicate.
func parseServiceConfigStartType(resp []byte) (uint32, error) {
	_, ret, err := parseServiceConfigTrailer(resp)
	if err != nil {
		return 0, err
	}
	if ret != 0 {
		return 0, svcRetError("RQueryServiceConfigW", ret)
	}
	data := resp[:len(resp)-12] // strip pcbBytesNeeded trailer
	for _, off := range []int{0, 4, 8} {
		if len(data) < off+36 {
			continue
		}
		svcType := binary.LittleEndian.Uint32(data[off:])
		startType := binary.LittleEndian.Uint32(data[off+4:])
		if plausibleServiceType(svcType) && startType <= svcctl.SERVICE_DISABLED {
			return startType, nil
		}
	}
	return 0, fmt.Errorf("RQueryServiceConfigW: no QUERY_SERVICE_CONFIGW fixed part found (%d bytes)", len(resp))
}

// plausibleServiceType reports whether t consists solely of valid MS-SCMR
// service-type bits (kernel/fs driver, adapter, recognizer, win32 own/share,
// interactive).
func plausibleServiceType(t uint32) bool {
	const valid = svcctl.SERVICE_KERNEL_DRIVER | svcctl.SERVICE_FILE_SYSTEM_DRIVER |
		svcctl.SERVICE_ADAPTER | svcctl.SERVICE_RECOGNIZER_DRIVER |
		svcctl.SERVICE_WIN32_OWN_PROCESS | svcctl.SERVICE_WIN32_SHARE_PROCESS |
		svcctl.SERVICE_INTERACTIVE_PROCESS
	return t != 0 && t&^valid == 0
}

// svcRetError renders an SCMR return code; mapSCMError rewrites the known
// ones at the method boundary.
func svcRetError(op string, code uint32) error {
	return fmt.Errorf("%s: 0x%08x", op, code)
}

// mapSCMError translates Win32 error codes surfaced by SCMR calls (rendered
// "0x%08x" by the helpers above) into plain-language messages. Feature-local
// per the package convention — the shared Describe mapping is untouched.
func mapSCMError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	hex := func(code uint32) string { return fmt.Sprintf("0x%08x", code) }
	switch {
	case strings.Contains(msg, hex(svcctl.ERROR_ACCESS_DENIED)):
		return fmt.Errorf("access denied (admin required)")
	case strings.Contains(msg, hex(svcctl.ERROR_SERVICE_DOES_NOT_EXIST)):
		return fmt.Errorf("no such service")
	case strings.Contains(msg, hex(win32ServiceDisabled)):
		return fmt.Errorf("the service is disabled — set its start type first")
	case strings.Contains(msg, hex(win32InvalidServiceControl)),
		strings.Contains(msg, hex(win32ServiceCannotAcceptCtrl)):
		return fmt.Errorf("the service does not accept stop/control requests")
	case strings.Contains(msg, hex(win32DependentServicesRunning)):
		return fmt.Errorf("other running services depend on this service")
	}
	return err
}
