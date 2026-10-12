package common

import (
	"golang.org/x/sys/unix"
	"net"
)

func SetMaxPacingRate(conn *net.TCPConn, rate uint64) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptUint64(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_MAX_PACING_RATE,
			rate,
		)
	})

	if err != nil {
		return err
	}
	return sockErr
}
