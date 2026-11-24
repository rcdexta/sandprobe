//go:build !darwin && !linux

package main

import "errors"

func makeRaw(fd int) (func(), error) {
	return nil, errors.New("raw mode unsupported on this platform")
}

func termSize(fd int) (cols, rows int) {
	return 0, 0
}

func isForegroundTTY(fd int) bool {
	return false
}

func pollFD(fd int, timeoutMS int) (ready, hup bool, err error) {
	return false, true, errors.New("poll unsupported on this platform")
}
