package smbclient

import (
	"fmt"
	"net"
	"time"
)

// CoerceMethod names a machine-account coercion trigger.
type CoerceMethod string

const (
	CoercePrinterBug   CoerceMethod = "printerbug"   // MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx
	CoercePetitPotam   CoerceMethod = "petitpotam"   // MS-EFSR EfsRpcOpenFileRaw
	CoerceShadowCoerce CoerceMethod = "shadowcoerce" // MS-FSRVP IsPathSupported
	CoerceDFSCoerce    CoerceMethod = "dfscoerce"    // MS-DFSNM NetrDfsAddStdRoot + RemoveStdRoot
)

// CoerceMethods lists every trigger the shell accepts, in help order.
var CoerceMethods = []CoerceMethod{CoercePrinterBug, CoercePetitPotam, CoerceShadowCoerce, CoerceDFSCoerce}

// ListenForCallback binds 0.0.0.0:port and waits up to timeout for one
// inbound connection — the proof that a coercion trigger made the
// target's machine account call home. connected=false with nil error
// means the wait expired quietly (patched target or filtered path);
// the shell renders that, not an error. The accepted connection is
// closed immediately; only the peer address is reported.
func ListenForCallback(port int, timeout time.Duration) (peer string, connected bool, err error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", false, fmt.Errorf("listen :%d: %v", port, err)
	}
	defer ln.Close()

	type result struct {
		peer string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- result{err: aerr}
			return
		}
		peer := conn.RemoteAddr().String()
		conn.Close()
		ch <- result{peer: peer}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return "", false, nil // listener closed on defer; treat as timeout
		}
		return r.peer, true, nil
	case <-time.After(timeout):
		return "", false, nil
	}
}
