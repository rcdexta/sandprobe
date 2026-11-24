//go:build darwin

package main

import (
	"bytes"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openPTY() (master, slave *os.File, err error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), unix.TIOCPTYGRANT, 0); errno != 0 {
		_ = unix.Close(mfd)
		return nil, nil, errno
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), unix.TIOCPTYUNLK, 0); errno != 0 {
		_ = unix.Close(mfd)
		return nil, nil, errno
	}
	var nameBuf [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&nameBuf[0]))); errno != 0 {
		_ = unix.Close(mfd)
		return nil, nil, errno
	}
	n := bytes.IndexByte(nameBuf[:], 0)
	if n < 0 {
		n = len(nameBuf)
	}
	sfd, err := unix.Open(string(nameBuf[:n]), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(mfd)
		return nil, nil, err
	}
	return os.NewFile(uintptr(mfd), "pty-master"), os.NewFile(uintptr(sfd), string(nameBuf[:n])), nil
}

func isCookedTTY(fd int) (bool, error) {
	tio, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return false, err
	}
	const want = unix.ICANON | unix.ECHO | unix.ISIG
	return tio.Lflag&want == want, nil
}
