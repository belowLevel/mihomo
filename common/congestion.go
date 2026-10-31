//go:build linux

package common

import (
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"net"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	BrutalAvailable   = true
	TCP_BRUTAL_PARAMS = 23301
)

type TCPBrutalParams struct {
	Rate     uint64
	CwndGain uint32
}

//go:linkname setsockopt syscall.setsockopt
func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)

func SetCongestionMaxPacingRate(conn net.Conn, congestion string, sendBPS uint64) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	syscallConn, loaded := common.Cast[syscall.Conn](tcpConn)
	if !loaded {
		return E.New(
			"cannot convert ", reflect.TypeOf(tcpConn), " to syscall.Conn, final type: ", reflect.TypeOf(common.Top(tcpConn)),
		)
	}
	return control.Conn(syscallConn, func(fd uintptr) error {
		var err error
		if congestion == "brutal" {
			if sendBPS > 0 {
				params := TCPBrutalParams{
					Rate:     sendBPS,
					CwndGain: 20, // hysteria2 default 20
				}
				err = setsockopt(int(fd), unix.IPPROTO_TCP, TCP_BRUTAL_PARAMS, unsafe.Pointer(&params), unsafe.Sizeof(params))
				if err != nil {
					return os.NewSyscallError("setsockopt IPPROTO_TCP TCP_BRUTAL_PARAMS ", err)
				}
			}
			return nil
		}
		if congestion != "" {
			err = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, congestion)
			if err != nil {
				return E.Extend(
					os.NewSyscallError("setsockopt IPPROTO_TCP TCP_CONGESTION ", err),
					"please make sure your system supports ", congestion,
				)
			}
		}
		if sendBPS > 0 {
			err = SetMaxPacingRate(tcpConn, sendBPS)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
