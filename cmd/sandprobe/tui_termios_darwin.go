//go:build darwin

package main

import "golang.org/x/sys/unix"

func makeRaw(fd int) (func(), error) {
	orig, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	raw := *orig
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &raw); err != nil {
		return nil, err
	}
	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TIOCSETA, orig)
	}, nil
}

func termSize(fd int) (cols, rows int) {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil || ws == nil {
		return 0, 0
	}
	return int(ws.Col), int(ws.Row)
}

func isForegroundTTY(fd int) bool {
	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || pgrp <= 0 {
		return true
	}
	return pgrp == unix.Getpgrp()
}

func pollFD(fd int, timeoutMS int) (ready, hup bool, err error) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, timeoutMS)
	if err != nil {
		return false, false, err
	}
	rev := pfd[0].Revents
	return n > 0 && rev&unix.POLLIN != 0, rev&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0, nil
}
